"""Phase 4a : sources de sous-domaines (subfinder -all, crtsh, amass), fusion `subdomains`,
archives (urlfinder → gau → waybackurls), carte, httpx #2 sur les seules URLs inédites.

Tout passe par de faux outils et un faux `urlopen` : aucun binaire, aucun accès réseau.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from recon_mano import modules, runner
from recon_mano.liveness import split_httpx_rows
from recon_mano.merge import merge_folder
from recon_mano.modules import Options, build_modules
from recon_mano.pipeline import Status

from .test_modules import FakeCrtsh, FakeTools, fake_status, lines, make_ctx, run_dag, statuses

W = "https://www.example.com"
LIVE_CODES = {200, 301}


def flag(command, name):
    return command[command.index(name) + 1]


class Recorder:
    """Faux `run_command` minimal : note chaque appel et écrit une sortie standard prédéfinie."""

    def __init__(self, outputs=None):
        self.calls: list = []
        self.outputs = outputs or {}

    def __call__(self, command, label, watch=None, timeout=None, stdout_to=None, silent=True, stdin_from=None):
        self.calls.append({
            "command": list(command), "label": label, "timeout": timeout, "silent": silent,
            "stdout_to": stdout_to, "watch": watch,
            "stdin": stdin_from.read_text(encoding="utf-8") if stdin_from is not None else None,
            "stdin_path": stdin_from,
        })
        if stdout_to is not None:
            stdout_to.write_text(self.outputs.get(label, ""), encoding="utf-8")
        return 0, 0.1, ""


# --------------------------------------------------------------------------- #
# subfinder
# --------------------------------------------------------------------------- #


def test_subfinder_all_sources_is_the_new_default():
    assert Options(target="example.com").all_sources is True


def test_subfinder_command_has_all_by_default_and_not_when_turned_off(tmp_path, monkeypatch):
    _, _, tools = run_dag(tmp_path, monkeypatch)
    assert "-all" in tools.of("subfinder")[0]
    (tmp_path / "b").mkdir()
    _, _, tools = run_dag(tmp_path / "b", monkeypatch, all_sources=False)
    assert "-all" not in tools.of("subfinder")[0]


def test_subfinder_enumerates_every_scope_apex(tmp_path, monkeypatch):
    _, _, tools = run_dag(tmp_path, monkeypatch, scope=("example.com", "example.org"))
    command = tools.of("subfinder")[0]
    assert [command[i + 1] for i, a in enumerate(command) if a == "-d"] == ["example.com", "example.org"]


def test_skip_subfinder(tmp_path, monkeypatch):
    scheduler, _, tools = run_dag(tmp_path, monkeypatch, skip_subfinder=True)
    assert statuses(scheduler)["subfinder"] is Status.SKIPPED and "subfinder" not in tools.calls
    assert statuses(scheduler)["subdomains"] is Status.DONE            # crtsh suffit


# --------------------------------------------------------------------------- #
# amass : commande et lecture
# --------------------------------------------------------------------------- #


def test_amass_command_builder_and_parsing(tmp_path, monkeypatch):
    rec = Recorder({"amass subs": "www.example.com\napi.example.com 1.2.3.4\nWWW.example.com\nNo names were discovered\n"})
    monkeypatch.setattr(runner, "run_command", rec)
    count, _, rc = modules.stage_amass(["example.com", "example.org"], tmp_path / "01c_amass.txt", 15, 900)
    enum, subs = rec.calls
    assert enum["command"] == ["amass", "enum", "-passive", "-d", "example.com,example.org", "-timeout", "15", "-nocolor"]
    assert subs["command"] == ["amass", "subs", "-names", "-d", "example.com,example.org", "-nocolor"]
    # Jamais -active (trafic vers la cible), -o (absent de enum en v5) ni -silent (couperait la sortie).
    for call in (enum, subs):
        assert call["silent"] is False
        assert not {"-active", "-o", "-silent", "-brute"} & set(call["command"])
    assert enum["timeout"] == 900
    assert rc == 0 and count == 2
    assert lines(tmp_path / "01c_amass.txt") == ["api.example.com", "www.example.com"]
    assert not (tmp_path / "01c_amass.txt.raw").exists()


def test_amass_without_timeout_omits_the_flag(tmp_path, monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(runner, "run_command", rec)
    modules.stage_amass(["example.com"], tmp_path / "a.txt", None, None)
    assert "-timeout" not in rec.calls[0]["command"] and rec.calls[0]["timeout"] is None


def test_amass_module_default_timeout_scope_and_files(tmp_path, monkeypatch):
    tools = FakeTools(amass_names=["old.example.com", "evil.net", "x.example.com.evil.net"])
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, tools=tools)
    assert statuses(scheduler)["amass"] is Status.DONE
    assert lines(tmp_path / "01c_amass.txt") == ["old.example.com"]
    assert flag(tools.of("amass")[0], "-timeout") == "15"
    assert any(r.startswith("amass\tevil.net\t") for r in lines(tmp_path / "rejected_scope.tsv"))
    assert {m.name: m.timeout for m in build_modules(Options(target="example.com"))}["amass"] == 15 * 60


def test_amass_timeout_option(tmp_path, monkeypatch):
    _, _, tools = run_dag(tmp_path, monkeypatch, timeouts={"amass": 20 * 60})
    assert flag(tools.of("amass")[0], "-timeout") == "20"
    assert {m.name: m.timeout for m in build_modules(Options(target="x.com", timeouts={"amass": 1200}))}["amass"] == 1200
    unlimited = {m.name: m.timeout for m in build_modules(Options(target="x.com", timeouts={"amass": None}))}
    assert unlimited["amass"] is None


def test_amass_passive_uses_every_scope_apex(tmp_path, monkeypatch):
    _, _, tools = run_dag(tmp_path, monkeypatch, scope=("example.com", "example.org"))
    assert flag(tools.of("amass")[0], "-d") == "example.com,example.org"


def test_amass_failure_without_names_fails_the_module_not_the_pipeline(tmp_path, monkeypatch):
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, tools=FakeTools(amass_rc=1))
    assert statuses(scheduler)["amass"] is Status.FAILED and "code 1" in scheduler.records["amass"].note
    assert statuses(scheduler)["subdomains"] is Status.DONE and statuses(scheduler)["httpx2"] is Status.DONE


def test_amass_killed_at_deadline_keeps_names_already_found(tmp_path, monkeypatch):
    tools = FakeTools(amass_rc=124, amass_names=["partial.example.com"])
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, tools=tools)
    assert statuses(scheduler)["amass"] is Status.DONE
    assert "partial.example.com" in lines(tmp_path / "01_subdomains.txt")


# --------------------------------------------------------------------------- #
# subdomains : fusion et entrée de dnsx
# --------------------------------------------------------------------------- #


def test_subdomains_merges_the_three_sources_and_feeds_dnsx(tmp_path, monkeypatch):
    tools = FakeTools(hosts=["www.example.com", "sub.example.com", "evil.net"], amass_names=["amass.example.com", "www.example.com"])
    crt = FakeCrtsh(script=[[{"name_value": "crt.example.com\nWWW.example.com\n*.wild.example.com\nsub.example.com"}]])
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, tools=tools, crtsh_fake=crt)
    assert lines(tmp_path / "01_subfinder.txt") == ["www.example.com", "sub.example.com"]      # sortie brute de subfinder, intacte
    assert lines(tmp_path / "01_subdomains.txt") == [
        "www.example.com", "sub.example.com", "crt.example.com", "wild.example.com", "amass.example.com",
    ]                                                                                             # dédoublonné, insensible à la casse
    assert flag(tools.of("dnsx")[0], "-l") == str(tmp_path / "01_subdomains.txt")
    assert "crt.example.com" in lines(tmp_path / "04_httpx_input.txt")
    rec = scheduler.records["subdomains"]
    assert rec.status is Status.DONE and rec.count == 5 and "crtsh 4" in rec.note
    modules_by_name = {m.name: m for m in build_modules(Options(target="example.com"))}
    assert modules_by_name["subdomains"].deps == ["subfinder", "crtsh", "amass"]
    assert modules_by_name["dnsx"].deps == ["subdomains"]


def test_dnsx_fallback_when_it_finds_nothing_uses_the_merged_list(tmp_path, monkeypatch):
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, missing={"dnsx"})
    assert statuses(scheduler)["dnsx"] is Status.DISABLED
    assert "api.example.com" in lines(tmp_path / "04_httpx_input.txt")


def test_sources_run_in_parallel_and_subdomains_waits_for_all(tmp_path, monkeypatch):
    tools = FakeTools(delays={"amass": 0.4})
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, tools=tools)
    r = scheduler.records
    assert r["subfinder"].start < r["amass"].end and r["crtsh"].start < r["amass"].end
    assert r["amass"].start < r["subfinder"].end                      # tous démarrent ensemble
    assert r["subdomains"].start >= max(r[n].end for n in ("subfinder", "crtsh", "amass")) - 1e-3
    assert r["dnsx"].start >= r["subdomains"].end - 1e-3


def test_stale_source_files_are_ignored(tmp_path, monkeypatch):
    (tmp_path / "01b_crtsh.txt").write_text("stale-crt.example.com\n", encoding="utf-8")
    (tmp_path / "01c_amass.txt").write_text("stale-amass.example.com\n", encoding="utf-8")
    run_dag(tmp_path, monkeypatch, crtsh=False, amass=False)
    merged = lines(tmp_path / "01_subdomains.txt")
    assert "stale-crt.example.com" not in merged and "stale-amass.example.com" not in merged
    assert "www.example.com" in merged


def test_provided_subdomains_replace_subfinder_but_passive_sources_still_add(tmp_path, monkeypatch):
    provided = tmp_path / "ffuf.txt"
    provided.write_text("ffuf.example.com\n", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    tools = FakeTools(amass_names=["amass.example.com"])
    crt = FakeCrtsh(script=[[{"name_value": "crt.example.com"}]])
    run_dag(out, monkeypatch, tools=tools, crtsh_fake=crt, subdomains=str(provided))
    assert "subfinder" not in tools.calls                                           # la liste remplace subfinder
    assert lines(out / "01_subfinder.txt") == ["ffuf.example.com"]
    assert lines(out / "01_subdomains.txt") == ["ffuf.example.com", "crt.example.com", "amass.example.com"]

    (tmp_path / "off").mkdir()
    run_dag(tmp_path / "off", monkeypatch, subdomains=str(provided), crtsh=False, amass=False)
    assert lines(tmp_path / "off" / "01_subdomains.txt") == ["ffuf.example.com"]    # flags off : uniquement la liste


def test_provided_subdomains_survive_skip_subfinder(tmp_path, monkeypatch):
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, subdomains="only.example.com", skip_subfinder=True, crtsh=False, amass=False)
    assert lines(tmp_path / "01_subdomains.txt") == ["only.example.com"]


# --------------------------------------------------------------------------- #
# Modules désactivés par option ou binaire manquant
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("module, tool", [("crtsh", None), ("amass", "amass"), ("gau", "gau"), ("waybackurls", "waybackurls")])
def test_each_new_module_can_be_turned_off(tmp_path, monkeypatch, module, tool):
    fake = FakeCrtsh()
    scheduler, _, tools = run_dag(tmp_path, monkeypatch, crtsh_fake=fake, **{module: False})
    rec = scheduler.records[module]
    assert rec.status is Status.SKIPPED and "option" in rec.note
    if tool:
        assert tool not in tools.calls
    else:
        assert fake.requests == []
    others = [n for n in statuses(scheduler) if n != module and not n.startswith("nuclei")]
    assert all(statuses(scheduler)[n] is Status.DONE for n in others), statuses(scheduler)


@pytest.mark.parametrize("binary", ["amass", "gau", "waybackurls"])
def test_missing_binary_disables_only_that_module(tmp_path, monkeypatch, binary):
    scheduler, _, tools = run_dag(tmp_path, monkeypatch, missing={binary})
    rec = scheduler.records[binary]
    assert rec.status is Status.DISABLED and rec.note == f"binaire {binary} introuvable — module désactivé"
    assert binary not in tools.calls
    for name in ("subdomains", "httpx", "merge_map", "httpx2", "tree"):
        assert statuses(scheduler)[name] is Status.DONE, name
    assert not scheduler.failed


def test_new_modules_default_to_enabled_and_are_listed_in_the_dag():
    modules_by_name = {m.name: m for m in build_modules(Options(target="example.com"))}
    for name in ("crtsh", "amass", "subdomains", "gau", "waybackurls"):
        assert modules_by_name[name].enabled, name
    assert modules_by_name["crtsh"].binaries == [] and not modules_by_name["crtsh"].network
    assert modules_by_name["amass"].binaries == ["amass"] and modules_by_name["gau"].binaries == ["gau"]
    assert modules_by_name["waybackurls"].binaries == ["waybackurls"]
    for name in ("crtsh", "amass", "gau", "waybackurls", "subdomains"):     # interrogent des services publics, pas la cible
        assert modules_by_name[name].network is False and modules_by_name[name].rate == 0
    assert modules_by_name["nuclei1"].enabled is False and modules_by_name["nuclei2"].enabled is False


# --------------------------------------------------------------------------- #
# gau / waybackurls : commandes et sorties
# --------------------------------------------------------------------------- #


def test_gau_command_builder(tmp_path, monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(runner, "run_command", rec)
    dest = tmp_path / "03b_gau.txt"
    modules.stage_gau(["example.com", "example.org"], dest, 2, 45, "", 600)
    (call,) = rec.calls
    command = call["command"]
    assert command[0] == "gau" and command[-2:] == ["example.com", "example.org"]       # domaines en positionnel
    assert "--subs" in command and flag(command, "--threads") == "2" and flag(command, "--timeout") == "45"
    assert "png" in flag(command, "--blacklist").split(",") and "--providers" not in command
    assert "--o" not in command                      # gau ajoute à --o : on capture la sortie standard
    assert call["stdout_to"] == dest and call["silent"] is False and call["timeout"] == 600

    modules.stage_gau(["example.com"], dest, 1, 30, " wayback,otx ", None)
    assert flag(rec.calls[1]["command"], "--providers") == "wayback,otx"


def test_gau_replaces_a_stale_output_file(tmp_path, monkeypatch):
    dest = tmp_path / "03b_gau.txt"
    dest.write_text("https://old.example.com/stale\n", encoding="utf-8")
    monkeypatch.setattr(runner, "run_command", Recorder({"gau": f"{W}/new\n"}))
    modules.stage_gau(["example.com"], dest, 2, 45)
    assert lines(dest) == [f"{W}/new"]


def test_waybackurls_command_builder(tmp_path, monkeypatch):
    rec = Recorder({"waybackurls": f"{W}/a\nnot a url\nftp://x/y\n{W}/a\n"})
    monkeypatch.setattr(runner, "run_command", rec)
    dest, domains_file = tmp_path / "03c.txt", tmp_path / "domains.tmp"
    count, _, _ = modules.stage_waybackurls(["example.com", "example.org"], dest, domains_file, 600)
    (call,) = rec.calls
    assert call["command"] == ["waybackurls"]                    # pas de -no-subs : sous-domaines inclus
    assert call["stdin"].split() == ["example.com", "example.org"]    # sans argument il lit un domaine par ligne
    assert call["silent"] is False and call["stdout_to"] == dest and call["timeout"] == 600
    assert not domains_file.exists()
    assert count == 1 and lines(dest) == [f"{W}/a"]


def test_gau_and_waybackurls_through_the_dag(tmp_path, monkeypatch):
    tools = FakeTools(
        gau_urls=[f"{W}/a?x=1", "http://www.example.com/b", "ftp://www.example.com/c", "https://evil.net/x", "pas une url", f"{W}/a?x=1"],
        wayback_urls=[f"{W}/old", "https://other.org/z", "https://cdn.thirdparty.io/q.js"],
    )
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, tools=tools)
    assert statuses(scheduler)["gau"] is Status.DONE and statuses(scheduler)["waybackurls"] is Status.DONE
    assert lines(tmp_path / "03b_gau.txt") == [f"{W}/a?x=1", "http://www.example.com/b"]
    assert lines(tmp_path / "03c_waybackurls.txt") == [f"{W}/old"]
    stages = {r.split("\t")[0] for r in lines(tmp_path / "rejected_scope.tsv")}
    assert {"gau", "waybackurls"} <= stages
    assert tools.wayback_stdin.split() == ["example.com"]
    assert not list(tmp_path.glob(".waybackurls*"))
    for label in ("amass", "amass subs", "gau", "waybackurls"):          # aucun -silent injecté par run_command
        assert tools.silent[label] is False, label


def test_archive_tools_use_every_scope_apex(tmp_path, monkeypatch):
    _, _, tools = run_dag(tmp_path, monkeypatch, scope=("example.com", "example.org"))
    assert tools.of("gau")[0][-2:] == ["example.com", "example.org"]
    assert tools.wayback_stdin.split() == ["example.com", "example.org"]


def test_archives_are_serialised_but_parallel_with_the_rest(tmp_path, monkeypatch):
    tools = FakeTools(delays={"gau": 0.2, "waybackurls": 0.4, "subfinder": 0.4, "dnsx": 0.3})
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, tools=tools)
    r = scheduler.records
    assert r["gau"].start >= r["urlfinder"].end - 1e-3                # urlfinder → gau
    assert r["waybackurls"].start >= r["gau"].end - 1e-3              # gau → waybackurls
    # …mais la chaîne tourne en parallèle des hôtes : subfinder et dnsx.
    assert r["gau"].start < r["subfinder"].end
    assert r["waybackurls"].start < r["dnsx"].end and r["dnsx"].start < r["waybackurls"].end
    # Les trois outils d'archive ne se chevauchent jamais.
    spans = sorted([tools.spans["urlfinder"], tools.spans["gau"], tools.spans["waybackurls"]])
    assert all(spans[i][1] <= spans[i + 1][0] + 1e-3 for i in range(2))
    modules_by_name = {m.name: m for m in build_modules(Options(target="example.com"))}
    assert modules_by_name["gau"].deps == ["urlfinder"] and modules_by_name["waybackurls"].deps == ["gau"]
    assert modules_by_name["httpx"].deps == ["dnsx", "urlfinder"]      # httpx #1 n'attend pas gau


def test_disabled_gau_does_not_block_waybackurls(tmp_path, monkeypatch):
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, gau=False)
    r = scheduler.records
    assert statuses(scheduler)["waybackurls"] is Status.DONE
    assert r["waybackurls"].start >= r["urlfinder"].end - 1e-3


def test_merge_map_waits_for_the_archive_chain_but_adds_little_in_typical_runs(tmp_path, monkeypatch):
    # Typique : la chaîne d'archives finit avant la fin de katana → merge_map ne perd rien.
    tools = FakeTools(delays={"katana": 0.5, "gau": 0.1, "waybackurls": 0.1})
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, tools=tools)
    r = scheduler.records
    assert r["merge_map"].start >= max(r[n].end for n in ("katana", "gau", "waybackurls")) - 1e-3
    assert r["merge_map"].start - r["katana"].end < 0.15

    # Chaîne plus lente que katana : merge_map (donc httpx #2) attend la fin des archives, pas plus.
    (tmp_path / "slow").mkdir()
    tools = FakeTools(delays={"katana": 0.05, "gau": 0.4, "waybackurls": 0.6})
    scheduler, _, _ = run_dag(tmp_path / "slow", monkeypatch, tools=tools)
    r = scheduler.records
    assert r["merge_map"].start >= r["waybackurls"].end - 1e-3
    assert r["merge_map"].start - r["waybackurls"].end < 0.15
    assert r["httpx2"].start >= r["merge_map"].end - 1e-3


# --------------------------------------------------------------------------- #
# Carte : périmètre, statiques, réduction
# --------------------------------------------------------------------------- #

PRODUITS = [f"{W}/produit/{i}" for i in range(1, 21)]
SEARCH = [f"{W}/search?q={c}" for c in "abcd"]
GAU = PRODUITS + SEARCH + [f"{W}/app.js", f"{W}/logo.png", "https://evil.net/x", f"{W}/admin"]
WAYBACK = [f"{W}/produit/{i}" for i in range(21, 26)] + [f"{W}/wb-only", f"{W}/doc.pdf"]


def test_archive_urls_are_scoped_static_excluded_and_reduced_to_k_per_signature(tmp_path, monkeypatch):
    tools = FakeTools(gau_urls=GAU, wayback_urls=WAYBACK)
    run_dag(tmp_path, monkeypatch, tools=tools)
    mapped = lines(tmp_path / "all_urls.txt")
    assert [u for u in mapped if "/produit/" in u] == PRODUITS[:3]          # K=3 (défaut), gau et waybackurls confondus
    assert [u for u in mapped if "/search" in u] == SEARCH[:3]
    assert f"{W}/admin" in mapped and f"{W}/wb-only" in mapped
    assert not [u for u in mapped if u.endswith((".js", ".png", ".pdf"))]    # statiques exclues
    assert "evil.net" not in "\n".join(mapped)


def test_archive_k_and_dedupe_options(tmp_path, monkeypatch):
    run_dag(tmp_path, monkeypatch, tools=FakeTools(gau_urls=GAU, wayback_urls=WAYBACK), archive_k=1)
    mapped = lines(tmp_path / "all_urls.txt")
    assert [u for u in mapped if "/produit/" in u] == PRODUITS[:1]

    (tmp_path / "off").mkdir()
    run_dag(tmp_path / "off", monkeypatch, tools=FakeTools(gau_urls=GAU, wayback_urls=WAYBACK), archive_dedupe=False)
    mapped = lines(tmp_path / "off" / "all_urls.txt")
    assert [u for u in mapped if "/produit/" in u] == PRODUITS + [f"{W}/produit/{i}" for i in range(21, 26)]
    assert not [u for u in mapped if u.endswith((".js", ".png", ".pdf"))]    # les statiques restent exclues
    assert "evil.net" not in "\n".join(mapped)


def test_archive_urls_never_reach_katana_or_nuclei_directly(tmp_path, monkeypatch):
    gau_only = "https://deep.example.com/only-in-gau"
    tools = FakeTools(gau_urls=[gau_only], wayback_urls=["https://deeper.example.com/only-in-wb"], codes={gau_only: 200})
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, tools=tools, nuclei=True)
    seeds = flag(tools.of("katana")[0], "-list")
    assert seeds == str(tmp_path / "urls_live.txt")
    seed_text = Path(seeds).read_text(encoding="utf-8")
    assert "only-in-gau" not in seed_text and "only-in-wb" not in seed_text
    assert "deep.example.com" not in (tmp_path / "07_nuclei1_input.txt").read_text(encoding="utf-8")
    assert "deep.example.com" not in (tmp_path / "04_httpx_input.txt").read_text(encoding="utf-8")   # httpx #1 non plus
    # Après httpx #2 seulement, l'URL validée peut servir à nuclei #2.
    assert gau_only in lines(tmp_path / "08_httpx2_input.txt")
    assert gau_only in lines(tmp_path / "urls_live_final.txt")
    assert gau_only in lines(tmp_path / "07_nuclei2_input.txt")


def test_unvalidated_archive_urls_do_not_leak_into_nuclei_without_httpx(tmp_path, monkeypatch):
    gau_only = "https://www.example.com/only-in-gau"
    tools = FakeTools(gau_urls=[gau_only])
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, tools=tools, nuclei=True, nuclei_passes="2", skip_httpx=True)
    assert statuses(scheduler)["httpx2"] is Status.SKIPPED
    assert gau_only in lines(tmp_path / "all_urls.txt")                            # elle est dans la carte…
    assert gau_only not in lines(tmp_path / "07_nuclei2_input.txt")                # …mais personne ne l'a validée
    assert lines(tmp_path / "07_nuclei2_input.txt")                                # le reste est bien scanné


def test_archive_urls_are_validated_by_httpx2_and_dead_ones_dropped(tmp_path, monkeypatch):
    base = "https://arch.example.com"
    ok, redirect, dead, boom, gone = (f"{base}/{n}" for n in ("ok", "redirect", "dead", "boom", "gone"))
    tools = FakeTools(
        gau_urls=[ok, dead, boom], wayback_urls=[redirect, gone],
        codes={ok: 200, redirect: 301, dead: 404, boom: 500}, unreachable=[gone],
    )
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, tools=tools, nuclei=True)
    sent = lines(tmp_path / "08_httpx2_input.txt")
    assert {ok, redirect, dead, boom, gone} <= set(sent)
    rows = [json.loads(l) for l in lines(tmp_path / "08_httpx2.jsonl")]
    assert gone not in {r["url"] for r in rows}                                        # timeout : httpx n'écrit rien
    assert lines(tmp_path / "urls_200_final.txt").count(ok) == 1
    live = lines(tmp_path / "urls_live_final.txt")
    assert ok in live and redirect in live
    for bad in (dead, boom, gone):
        assert bad not in live and bad not in lines(tmp_path / "urls_200_final.txt"), bad
        assert bad not in lines(tmp_path / "07_nuclei2_input.txt"), bad
    # …et ils entrent dans l'arbre HTML comme n'importe quel 200.
    assert "arch.example.com" in (tmp_path / "urls_tree.html").read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# httpx #2 : seulement les URLs inédites
# --------------------------------------------------------------------------- #


PORT_URL = "https://www.example.com:8080"      # service hors 80/443 que le faux naabu « ouvre » sur www.example.com


def legacy_finals(tmp_path, tools, map_urls):
    """Ce que l'ancien httpx #2 (carte entière re-testée) aurait produit avec le même faux httpx,
    plus les services hors 80/443 (httpx ports) qui rejoignent les listes finales."""
    rows = [
        {"url": u, "status_code": tools.codes.get(u) or fake_status(u)}
        for u in list(map_urls) + [PORT_URL] if u not in tools.unreachable
    ]
    out = {k: tmp_path / f"legacy_{k}.txt" for k in ("all", "200", "live")}
    split_httpx_rows(rows, out["all"], out["200"], out["live"], LIVE_CODES)
    return {k: sorted(lines(p)) for k, p in out.items()}


def final_sets(folder):
    return {
        "all": sorted(lines(folder / "urls_all_final.txt")),
        "200": sorted(lines(folder / "urls_200_final.txt")),
        "live": sorted(lines(folder / "urls_live_final.txt")),
    }


def test_httpx2_tests_only_unseen_urls(tmp_path, monkeypatch):
    tools = FakeTools(gau_urls=GAU[:6] + [f"{W}/admin"], wayback_urls=[f"{W}/wb-only"])
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, tools=tools)
    first = [json.loads(l) for l in lines(tmp_path / "05_httpx.jsonl")]
    seen = {r["url"] for r in first} | {r["input"] for r in first if "input" in r}
    map_urls = lines(tmp_path / "all_urls.txt")
    sent = lines(tmp_path / "08_httpx2_input.txt")
    assert sent and set(sent) == set(map_urls) - seen
    assert len(sent) < len(map_urls)                                   # les seeds d'httpx #1 ne sont pas re-testées
    (command,) = tools.of("httpx #2")
    assert flag(command, "-l") == str(tmp_path / "08_httpx2_input.txt")
    new_rows = [json.loads(l) for l in lines(tmp_path / "08_httpx2.jsonl")]
    assert {r["url"] for r in new_rows} <= set(sent) and not ({r["url"] for r in new_rows} & seen)
    assert "réutilisées" in scheduler.records["httpx2"].note


def test_final_lists_are_identical_to_the_old_full_revalidation(tmp_path, monkeypatch):
    tools = FakeTools(
        gau_urls=GAU, wayback_urls=WAYBACK,
        codes={f"{W}/admin": 403, f"{W}/wb-only": 200, f"{W}/search?q=a": 404, f"{W}/produit/1": 500},
        unreachable=[f"{W}/produit/2"],
    )
    run_dag(tmp_path, monkeypatch, tools=tools)
    assert final_sets(tmp_path) == legacy_finals(tmp_path, tools, lines(tmp_path / "all_urls.txt"))


def test_final_lists_identical_when_nothing_new_to_test(tmp_path, monkeypatch):
    # Sans katana ni archives : la carte = les seeds, tout est déjà validé → httpx #2 ne lance rien.
    tools = FakeTools()
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, tools=tools, skip_katana=True, gau=False, waybackurls=False)
    assert statuses(scheduler)["httpx2"] is Status.DONE
    assert tools.of("httpx #2") == []                                    # aucune passe réseau
    assert lines(tmp_path / "08_httpx2_input.txt") == [] and (tmp_path / "08_httpx2.jsonl").read_text(encoding="utf-8") == ""
    assert final_sets(tmp_path) == legacy_finals(tmp_path, tools, lines(tmp_path / "all_urls.txt"))
    assert lines(tmp_path / "urls_200_final.txt")


def test_httpx2_ignores_a_stale_first_pass_file(tmp_path, monkeypatch):
    # 05_httpx.jsonl d'un run précédent ne doit rien « valider » si httpx #1 n'a pas tourné dans CE run.
    tools = FakeTools()
    monkeypatch.setattr(runner, "run_command", tools)
    ctx = make_ctx(tmp_path)
    (tmp_path / "05_httpx.jsonl").write_text(json.dumps({"url": f"{W}/admin", "status_code": 200}) + "\n", encoding="utf-8")
    (tmp_path / "all_urls.txt").write_text(f"{W}/admin\n{W}/other\n", encoding="utf-8")
    ctx.state.update(subfinder_count=1, map_total=2)             # httpx_ran absent : httpx #1 n'a pas tourné
    ctx.rate = 50
    modules.run_httpx2(ctx)
    assert lines(tmp_path / "08_httpx2_input.txt") == [f"{W}/admin", f"{W}/other"]

    ctx.state["httpx_ran"] = True                                 # httpx #1 a tourné : /admin est déjà connue
    modules.run_httpx2(ctx)
    assert lines(tmp_path / "08_httpx2_input.txt") == [f"{W}/other"]
    assert f"{W}/admin" in "\n".join(lines(tmp_path / "urls_all_final.txt"))     # reprise de la ligne d'httpx #1


def test_missing_httpx_disables_httpx2_too(tmp_path, monkeypatch):
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, missing={"httpx"})
    assert statuses(scheduler)["httpx2"] is Status.DISABLED


def test_nothing_leaves_the_scope(tmp_path, monkeypatch):
    tools = FakeTools(
        hosts=["www.example.com", "evil.net"], amass_names=["amass.evil.net", "a.example.com"],
        gau_urls=["https://evil.net/g", f"{W}/g"], wayback_urls=["https://other.org/w", f"{W}/w"],
    )
    crt = FakeCrtsh(script=[[{"name_value": "crt.evil.net\nc.example.com\nexample.com.evil.net"}]])
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, tools=tools, crtsh_fake=crt, nuclei=True)
    assert not scheduler.failed
    for path in tmp_path.iterdir():
        if path.name == "rejected_scope.tsv" or path.is_dir():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for outside in ("evil.net", "other.org", "thirdparty.io"):
            assert outside not in text, f"{outside} dans {path.name}"
    assert "amass.evil.net" in (tmp_path / "rejected_scope.tsv").read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# Fusion finale : toutes les sources, rejouée par `recon_mano merge`
# --------------------------------------------------------------------------- #


def write_config(folder, **extra):
    config = {
        "target": "example.com",
        "scope": {"enabled": True, "apexes": ["example.com"], "excludes": []},
        "live_codes": sorted(LIVE_CODES),
        "archive": {"dedupe": True, "k": 3},
    }
    config.update(extra)
    (folder / "run_config.json").write_text(json.dumps(config), encoding="utf-8")


def test_every_source_flows_into_the_final_lists_and_merge_replays_them(tmp_path, monkeypatch):
    urlfinder_url = "https://www.example.com/old"            # urlfinder (ARCHIVE du faux outil)
    tools = FakeTools(
        gau_urls=[f"{W}/from-gau"], wayback_urls=[f"{W}/from-wayback"],
        codes={u: 200 for u in (urlfinder_url, f"{W}/from-gau", f"{W}/from-wayback", f"{W}/admin")},
    )
    run_dag(tmp_path, monkeypatch, tools=tools)
    finals = final_sets(tmp_path)
    expected = {urlfinder_url, f"{W}/from-gau", f"{W}/from-wayback", f"{W}/admin"}     # urlfinder, gau, waybackurls, katana
    assert expected <= set(lines(tmp_path / "urls_200_final.txt"))
    assert "from-wayback" in (tmp_path / "urls_tree.html").read_text(encoding="utf-8")

    # Rejeu : on détruit tout ce que merge reconstruit, puis on le relit depuis les fichiers du disque.
    map_before = lines(tmp_path / "all_urls.txt")
    for name in ("all_urls.txt", "urls_all_final.txt", "urls_200_final.txt", "urls_live_final.txt", "urls_tree.html"):
        (tmp_path / name).unlink()
    write_config(tmp_path)
    result = merge_folder(tmp_path)
    assert sorted(lines(tmp_path / "all_urls.txt")) == sorted(map_before)
    assert final_sets(tmp_path) == finals
    assert dict(result.rebuilt)["all_urls.txt"] == len(map_before)
    assert (tmp_path / "urls_tree.html").exists()


def test_merge_replay_reads_scope_and_archive_settings_from_run_config(tmp_path, monkeypatch):
    tools = FakeTools(gau_urls=GAU, wayback_urls=WAYBACK, codes={f"{W}/produit/3": 200})
    run_dag(tmp_path, monkeypatch, tools=tools)

    write_config(tmp_path, archive={"dedupe": False, "k": 3})
    merge_folder(tmp_path)
    mapped = lines(tmp_path / "all_urls.txt")
    assert [u for u in mapped if "/produit/" in u] == PRODUITS + [f"{W}/produit/{i}" for i in range(21, 26)]

    write_config(tmp_path, archive={"dedupe": True, "k": 1})
    merge_folder(tmp_path)
    assert [u for u in lines(tmp_path / "all_urls.txt") if "/produit/" in u] == PRODUITS[:1]

    # Une exclusion ajoutée après coup retire l'hôte de la carte ET des listes finales.
    write_config(tmp_path, scope={"enabled": True, "apexes": ["example.com"], "excludes": ["www.example.com"]})
    merge_folder(tmp_path)
    for name in ("all_urls.txt", "urls_all_final.txt", "urls_200_final.txt", "urls_live_final.txt"):
        assert "www.example.com" not in "\n".join(lines(tmp_path / name)), name


def test_merge_unions_first_and_second_httpx_passes(tmp_path):
    (tmp_path / "urls_live.txt").write_text(f"{W}/seed\n{W}/seed2\n", encoding="utf-8")
    (tmp_path / "06_katana.txt").write_text(f"{W}/crawled\n", encoding="utf-8")
    (tmp_path / "03b_gau.txt").write_text(f"{W}/archive\n{W}/script.js\nhttps://evil.net/x\n", encoding="utf-8")
    first = [
        {"url": f"{W}/seed", "input": f"{W}/seed", "status_code": 200},
        {"url": f"{W}/seed2", "status_code": 403},
        {"url": f"{W}/not-in-map", "status_code": 200},                  # testée par httpx #1 mais jamais en carte
    ]
    second = [{"url": f"{W}/crawled", "status_code": 301}, {"url": f"{W}/archive", "status_code": 200}]
    (tmp_path / "05_httpx.jsonl").write_text("".join(json.dumps(r) + "\n" for r in first), encoding="utf-8")
    (tmp_path / "08_httpx2.jsonl").write_text("".join(json.dumps(r) + "\n" for r in second), encoding="utf-8")
    write_config(tmp_path, live_codes=[200, 301])
    merge_folder(tmp_path)
    assert lines(tmp_path / "all_urls.txt") == [f"{W}/seed", f"{W}/seed2", f"{W}/crawled", f"{W}/archive"]
    assert sorted(lines(tmp_path / "urls_200_final.txt")) == sorted([f"{W}/seed", f"{W}/archive"])
    assert lines(tmp_path / "urls_live_final.txt") == [f"{W}/seed", f"{W}/crawled", f"{W}/archive"]   # 403 hors codes vivants
    assert f"{W}/not-in-map" not in "\n".join(lines(tmp_path / "urls_all_final.txt"))
