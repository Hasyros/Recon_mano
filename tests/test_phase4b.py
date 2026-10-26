"""Phase 4b dans le DAG réel : katana (réponses stockées) → jsluice / secrets, takeover,
naabu → httpx ports → nuclei ports, arjun → nuclei #2. Faux outils, aucun réseau.
"""

from __future__ import annotations

import hashlib
import json
import shutil

import pytest
from typer.testing import CliRunner

from recon_mano import runner, signatures
from recon_mano.cli import clean_artifacts
from recon_mano.config import MODULE_DEFAULTS
from recon_mano.merge import merge_folder
from recon_mano.modules import Options, build_modules, finalize_nuclei, run_httpx_ports, run_naabu, run_takeover
from recon_mano.pipeline import ModuleError, ModuleSkipped, Scheduler, Status, build_paths, DEFAULT_WORKERS

from .test_config import app, fake_environment, params
from .test_modules import FAKE_KEY, FAKE_SECRET, FakeTools, lines, make_ctx, run_dag, statuses
from .test_sources import flag, write_config

W = "https://www.example.com"
PORT_URL = f"{W}:8080"


def read(path):
    return path.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# Registre et DAG
# --------------------------------------------------------------------------- #


def test_new_modules_are_registered_on_by_default_with_the_right_network_flags():
    modules = {m.name: m for m in build_modules(Options(target="example.com"))}
    for name in ("jsluice", "secrets", "takeover", "naabu", "httpx_ports", "arjun"):
        assert modules[name].enabled, name                            # tout est actif par défaut…
    assert modules["nuclei_ports"].enabled is False                   # …sauf nuclei (opt-in)
    assert [n for n, d in MODULE_DEFAULTS.items() if not d.enabled] == ["nuclei1", "nuclei_ports", "nuclei2"]
    # Hors ligne (fichiers locaux) : aucun budget de débit.
    for name in ("jsluice", "secrets"):
        assert not modules[name].network and modules[name].rate == 0, name
    # Ce qui parle à la cible consomme le budget, avec un débit et un timeout prudents par défaut.
    for name in ("takeover", "naabu", "httpx_ports", "nuclei_ports", "arjun"):
        assert modules[name].network and modules[name].rate > 0, name
    for name in ("jsluice", "secrets", "takeover", "naabu", "httpx_ports", "nuclei_ports", "arjun"):
        assert modules[name].timeout, name
    assert (modules["naabu"].rate, modules["arjun"].rate, modules["takeover"].rate) == (100, 20, 10)
    assert modules["secrets"].binaries == [] and modules["secrets"].binaries_any == ["trufflehog", "gitleaks"]
    assert modules["takeover"].binaries == ["dnsx"]                   # subzy est facultatif (candidats seuls sans lui)


def test_dag_dependencies():
    modules = {m.name: m for m in build_modules(Options(target="example.com"))}
    assert modules["jsluice"].deps == ["katana"] and modules["secrets"].deps == ["katana", "jsluice"]
    # + httpx : ne pas démarrer avant httpx #1 (chemin critique) ni lui prendre du budget.
    assert modules["takeover"].deps == ["dnsx", "httpx"] and modules["naabu"].deps == ["dnsx", "httpx"]
    assert modules["httpx_ports"].deps == ["naabu"] and modules["nuclei_ports"].deps == ["httpx_ports"]
    assert modules["merge_map"].deps == ["katana", "gau", "waybackurls", "jsluice"]
    assert modules["httpx2"].deps == ["merge_map", "httpx_ports"]
    assert modules["arjun"].deps == ["httpx2"] and modules["nuclei2"].deps == ["httpx2", "arjun"]
    order = [m.name for m in build_modules(Options(target="example.com"))]
    # katana (et nuclei #1) gardent la priorité du budget sur takeover / naabu.
    assert order.index("nuclei1") < order.index("katana") < order.index("takeover") < order.index("naabu")


def test_default_workers_is_six():
    assert DEFAULT_WORKERS == 6 and params()["workers"].default == 6


def test_full_dag_with_all_new_modules_runs_to_completion_in_parallel_and_sequentially(tmp_path, monkeypatch):
    (tmp_path / "p").mkdir()
    (tmp_path / "s").mkdir()
    scheduler, parallel_ctx, _ = run_dag(tmp_path / "p", monkeypatch, nuclei=True)
    assert all(s is Status.DONE for s in statuses(scheduler).values()), statuses(scheduler)
    finalize_nuclei(parallel_ctx)

    monkeypatch.setattr(runner, "run_command", FakeTools())
    options = Options(target="example.com", urlfinder_retries=0, live_code_set={200, 301}, nuclei=True)
    ctx = make_ctx(tmp_path / "s", nuclei=True)
    seq = Scheduler(build_modules(ctx.options), ctx, max_workers=1, live=False, poll=0.01)
    seq.run()                                                          # sans interblocage
    assert all(s is Status.DONE for s in statuses(seq).values()), statuses(seq)
    finalize_nuclei(ctx)
    # (09_jsluice_secrets.jsonl et 10_secrets.jsonl contiennent des chemins absolus du dossier de sortie : exclus.)
    for name in ("09_jsluice_urls.txt", "10_secrets.txt", "11_dnsx_cname.jsonl",
                 "11_takeover_candidates.txt", "11_takeover.jsonl", "11_takeover.txt", "12_naabu.jsonl", "12_ports.txt",
                 "13_httpx_ports_input.txt", "13_httpx_ports.jsonl", "urls_live_ports.txt", "07_nuclei_ports_input.txt",
                 "nuclei_ports.jsonl", "14_arjun_input.txt", "14_arjun.json", "14_arjun_params.txt", "07_nuclei2_params.txt",
                 "all_urls.txt", "urls_all_final.txt", "urls_live_final.txt", "nuclei.txt", "urls_tree.html"):
        assert (tmp_path / "p" / name).read_bytes() == (tmp_path / "s" / name).read_bytes(), name


# --------------------------------------------------------------------------- #
# katana : réponses stockées
# --------------------------------------------------------------------------- #


def test_katana_stores_responses_by_default_and_documents_disk_use(tmp_path, monkeypatch):
    scheduler, ctx, tools = run_dag(tmp_path, monkeypatch)
    command = tools.of("katana")[0]
    assert "-store-response" in command and flag(command, "-store-response-dir") == str(tmp_path / "responses" / "katana")
    assert (tmp_path / "responses" / "katana" / "index.txt").exists()
    assert "réponses stockées" in scheduler.records["katana"].note


def test_no_katana_store_drops_the_flags_and_skips_jsluice_and_secrets(tmp_path, monkeypatch):
    scheduler, _, tools = run_dag(tmp_path, monkeypatch, katana_store=False)
    assert not {"-store-response", "-store-response-dir"} & set(tools.of("katana")[0])
    for name in ("jsluice", "secrets"):
        assert statuses(scheduler)[name] is Status.SKIPPED and "--no-katana-store" in scheduler.records[name].note
    assert "jsluice" not in tools.calls and "trufflehog" not in tools.calls
    assert not (tmp_path / "responses").exists() and not (tmp_path / "09_jsluice_urls.txt").exists()


def test_stale_responses_are_never_reused(tmp_path, monkeypatch):
    stale = tmp_path / "responses" / "katana"
    stale.mkdir(parents=True)
    (stale / "index.txt").write_text("stale\n", encoding="utf-8")
    scheduler, _, tools = run_dag(tmp_path, monkeypatch, skip_katana=True)         # katana ne tourne pas dans ce run
    assert statuses(scheduler)["jsluice"] is Status.SKIPPED and statuses(scheduler)["secrets"] is Status.SKIPPED
    assert "jsluice" not in tools.calls and "trufflehog" not in tools.calls
    # …et quand katana tourne, le dossier repart de zéro.
    (tmp_path / "b").mkdir()
    stale = tmp_path / "b" / "responses" / "katana"
    stale.mkdir(parents=True)
    (stale / "old.txt").write_text("ancien\n", encoding="utf-8")
    run_dag(tmp_path / "b", monkeypatch)
    assert not (stale / "old.txt").exists()


# --------------------------------------------------------------------------- #
# jsluice
# --------------------------------------------------------------------------- #


def test_jsluice_resolves_endpoints_against_the_js_url_and_feeds_the_map(tmp_path, monkeypatch):
    scheduler, ctx, tools = run_dag(tmp_path, monkeypatch)
    assert statuses(scheduler)["jsluice"] is Status.DONE
    urls = lines(tmp_path / "09_jsluice_urls.txt")
    assert urls == [f"{W}/api/v2/items?id=1", f"{W}/up", "https://api.example.com/graphql", f"{W}/static/js/lib/rel".replace("/js", "")]
    # Un seul JS en périmètre est analysé (celui du tiers et la page HTML sont écartés) : une commande par mode.
    (urls_cmd,) = tools.of("jsluice urls")
    (secrets_cmd,) = tools.of("jsluice secrets")
    assert urls_cmd[:2] == ["jsluice", "urls"] and secrets_cmd[:2] == ["jsluice", "secrets"]
    assert tools.silent["jsluice urls"] is False and tools.silent["jsluice secrets"] is False
    # Hôte tiers et expressions : écartés (et journalisés) ; temporaires et copies de JS nettoyés.
    assert "thirdparty.io" not in read(tmp_path / "09_jsluice_urls.txt")
    assert any(r.startswith("jsluice\tcdn.thirdparty.io\t") for r in lines(tmp_path / "rejected_scope.tsv"))
    assert not (tmp_path / "responses" / "js").exists() and not list(tmp_path.glob(".jsluice*"))
    # Non validés : ils entrent dans la carte, httpx #2 les teste, puis seulement ils servent.
    assert set(urls) <= set(lines(tmp_path / "all_urls.txt"))
    assert f"{W}/api/v2/items?id=1" in lines(tmp_path / "08_httpx2_input.txt")
    assert f"{W}/api/v2/items?id=1" in ctx.state["archive_only"]
    assert (tmp_path / "09_jsluice_secrets.jsonl").exists() and len(lines(tmp_path / "09_jsluice_secrets.jsonl")) == 1


def test_jsluice_endpoints_never_reach_nuclei_without_httpx_validation(tmp_path, monkeypatch):
    scheduler, _, tools = run_dag(tmp_path, monkeypatch, nuclei=True, nuclei_passes="2", skip_httpx=True)
    assert f"{W}/api/v2/items?id=1" in lines(tmp_path / "all_urls.txt")
    assert f"{W}/api/v2/items?id=1" not in lines(tmp_path / "07_nuclei2_input.txt")


def test_jsluice_skips_without_js_and_off_by_flag(tmp_path, monkeypatch):
    scheduler, _, tools = run_dag(tmp_path, monkeypatch, tools=FakeTools(store=False))
    assert statuses(scheduler)["jsluice"] is Status.SKIPPED and "index vide" in scheduler.records["jsluice"].note
    (tmp_path / "off").mkdir()
    scheduler, _, tools = run_dag(tmp_path / "off", monkeypatch, jsluice=False)
    assert statuses(scheduler)["jsluice"] is Status.SKIPPED and "option" in scheduler.records["jsluice"].note
    assert "jsluice" not in tools.calls and statuses(scheduler)["merge_map"] is Status.DONE


def test_missing_jsluice_binary_disables_only_that_module(tmp_path, monkeypatch):
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, missing={"jsluice"})
    rec = scheduler.records["jsluice"]
    assert rec.status is Status.DISABLED and rec.note == "binaire jsluice introuvable — module désactivé"
    assert statuses(scheduler)["secrets"] is Status.DONE and statuses(scheduler)["merge_map"] is Status.DONE
    assert not scheduler.failed


# --------------------------------------------------------------------------- #
# secrets
# --------------------------------------------------------------------------- #


def test_secrets_summary_is_redacted_and_the_console_never_shows_a_secret(tmp_path, monkeypatch, capsys):
    scheduler, _, tools = run_dag(tmp_path, monkeypatch)
    out = capsys.readouterr().out
    assert statuses(scheduler)["secrets"] is Status.DONE
    (command,) = tools.of("trufflehog")
    assert command[:3] == ["trufflehog", "filesystem", str(tmp_path / "responses" / "katana")]
    assert "--no-verification" in command and "--only-verified" not in command           # jamais de vérification
    assert tools.silent["trufflehog"] is False
    summary = lines(tmp_path / "10_secrets.txt")
    sha = hashlib.sha1(f"{W}/static/app.js".encode()).hexdigest()
    assert summary == [
        f"[AWS] {W}/static/app.js  (trufflehog, {sha}.txt:3)  wJal…",
        f"[AWSAccessKey] {W}/static/app.js  (jsluice, {sha}.js)  key=AKIA…, secret=wJal…",
    ]
    # Aucun secret entier dans le résumé ni dans la sortie du programme (console, notes du récapitulatif).
    for secret in (FAKE_KEY, FAKE_SECRET):
        assert secret not in read(tmp_path / "10_secrets.txt")
        assert secret not in out
        assert secret not in scheduler.records["secrets"].note
    assert "wJal…" in read(tmp_path / "10_secrets.txt") and "AKIA…" in read(tmp_path / "10_secrets.txt")
    # Le fichier brut garde la preuve (documenté comme sensible).
    assert FAKE_SECRET in read(tmp_path / "10_secrets.jsonl")
    assert "en clair" in out
    # Le secret d'un JS tiers (hors périmètre) n'entre pas dans le résumé.
    assert "thirdparty.io" not in read(tmp_path / "10_secrets.txt") and "thirdparty.io" not in read(tmp_path / "10_secrets.jsonl")
    assert any(r.startswith("secrets\tcdn.thirdparty.io\t") for r in lines(tmp_path / "rejected_scope.tsv"))
    assert scheduler.records["secrets"].count == 2 and "trufflehog" in scheduler.records["secrets"].note


def test_secrets_prefers_trufflehog_and_falls_back_to_gitleaks(tmp_path, monkeypatch, capsys):
    scheduler, _, tools = run_dag(tmp_path, monkeypatch, missing={"trufflehog"})
    out = capsys.readouterr().out
    assert statuses(scheduler)["secrets"] is Status.DONE and "trufflehog" not in tools.calls
    (command,) = tools.of("gitleaks")
    assert command[:3] == ["gitleaks", "dir", str(tmp_path / "responses" / "katana")]
    assert "aws-access-token" in read(tmp_path / "10_secrets.txt") and "gitleaks" in read(tmp_path / "10_secrets.txt")
    assert FAKE_SECRET not in read(tmp_path / "10_secrets.txt") and FAKE_SECRET not in out
    assert not list(tmp_path.glob(".secrets*"))


def test_secrets_disabled_when_no_scanner_and_off_by_flag(tmp_path, monkeypatch):
    scheduler, _, tools = run_dag(tmp_path, monkeypatch, missing={"trufflehog", "gitleaks"})
    rec = scheduler.records["secrets"]
    assert rec.status is Status.DISABLED and "trufflehog, gitleaks" in rec.note
    assert not {"trufflehog", "gitleaks"} & set(tools.calls) and not scheduler.failed
    assert not (tmp_path / "10_secrets.txt").exists()
    (tmp_path / "off").mkdir()
    scheduler, _, tools = run_dag(tmp_path / "off", monkeypatch, secrets=False)
    assert statuses(scheduler)["secrets"] is Status.SKIPPED and "trufflehog" not in tools.calls


def test_secrets_includes_jsluice_secrets_only_when_jsluice_ran_in_this_run(tmp_path, monkeypatch):
    run_dag(tmp_path, monkeypatch, jsluice=False)
    (tmp_path / "x").mkdir()
    (tmp_path / "09_jsluice_secrets.jsonl").write_text('{"kind":"Stale","data":"zzzzzzzzzzzz","filename":"x"}\n', encoding="utf-8")
    run_dag(tmp_path / "x", monkeypatch, jsluice=False)
    assert "jsluice" not in read(tmp_path / "10_secrets.txt") and "Stale" not in read(tmp_path / "10_secrets.txt")


# --------------------------------------------------------------------------- #
# takeover
# --------------------------------------------------------------------------- #


def test_takeover_tests_only_hosts_whose_cname_leaves_the_scope(tmp_path, monkeypatch):
    tools = FakeTools(hosts=["www.example.com", "shop.example.com", "lb.example.com", "plain.example.com", "dead.example.com"],
                      cnames={"www.example.com": ["app.herokudns.com."], "shop.example.com": ["lb.example.com."],
                              "lb.example.com": ["x.example.com."], "dead.example.com": ["bucket.s3.amazonaws.com"]},
                      vulnerable={"dead.example.com"})
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, tools=tools)
    cname_cmd = tools.of("dnsx cname")[0]
    assert flag(cname_cmd, "-l") == str(tmp_path / "02_dnsx.txt") and {"-cname", "-resp", "-json"} <= set(cname_cmd)
    assert lines(tmp_path / "11_takeover_candidates.txt") == ["www.example.com", "dead.example.com"]    # CNAME internes : non
    (subzy,) = tools.of("subzy")
    assert flag(subzy, "--targets") == str(tmp_path / "11_takeover_candidates.txt")
    assert flag(subzy, "--concurrency") == "5" and "--hide_fails" in subzy and "--verify_ssl" not in subzy
    assert tools.silent["subzy"] is False
    # Seuls les résultats vulnérables sont gardés.
    rows = [json.loads(l) for l in lines(tmp_path / "11_takeover.jsonl")]
    assert [r["subdomain"] for r in rows] == ["dead.example.com"]
    assert "dead.example.com" in read(tmp_path / "11_takeover.txt") and "www.example.com" not in read(tmp_path / "11_takeover.txt")
    assert scheduler.records["takeover"].count == 1 and not (tmp_path / ".subzy.tmp").exists()


def test_takeover_without_subzy_still_delivers_the_candidates(tmp_path, monkeypatch):
    scheduler, _, tools = run_dag(tmp_path, monkeypatch, missing={"subzy"})
    rec = scheduler.records["takeover"]
    assert rec.status is Status.DONE and "subzy introuvable" in rec.note and rec.count == 1      # terminé, pas désactivé
    assert lines(tmp_path / "11_takeover_candidates.txt") == ["www.example.com"]
    assert "subzy" not in tools.calls and not (tmp_path / "11_takeover.txt").exists()
    assert not scheduler.failed


def test_takeover_nothing_to_test_and_flags(tmp_path, monkeypatch):
    scheduler, _, tools = run_dag(tmp_path, monkeypatch, tools=FakeTools(cnames={"www.example.com": ["lb.example.com."]}))
    assert statuses(scheduler)["takeover"] is Status.DONE and "subzy" not in tools.calls
    assert scheduler.records["takeover"].note == "aucun CNAME hors périmètre" and lines(tmp_path / "11_takeover_candidates.txt") == []
    (tmp_path / "off").mkdir()
    scheduler, _, tools = run_dag(tmp_path / "off", monkeypatch, takeover=False)
    assert statuses(scheduler)["takeover"] is Status.SKIPPED and "dnsx cname" not in [l for l, _ in tools.commands]
    (tmp_path / "nodnsx").mkdir()
    scheduler, _, tools = run_dag(tmp_path / "nodnsx", monkeypatch, missing={"dnsx"})
    assert statuses(scheduler)["takeover"] is Status.DISABLED                # sans dnsx : pas de CNAME, module désactivé
    assert not scheduler.failed


def test_takeover_concurrency_never_exceeds_the_granted_rate(tmp_path, monkeypatch):
    scheduler, _, tools = run_dag(tmp_path, monkeypatch, takeover_concurrency=50, takeover_rate=3)
    assert scheduler.records["takeover"].rate == 3
    assert flag(tools.of("subzy")[0], "--concurrency") == "3"


# --------------------------------------------------------------------------- #
# naabu → httpx ports → nuclei ports
# --------------------------------------------------------------------------- #


def test_naabu_command_ports_scope_and_files(tmp_path, monkeypatch):
    tools = FakeTools(extra_ports=[("api.evil.net", 8443)])
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, tools=tools)
    (command,) = tools.of("naabu")
    assert flag(command, "-list") == str(tmp_path / "02_dnsx.txt")                  # hôtes vivants seulement
    assert flag(command, "-top-ports") == "1000" and "-exclude-cdn" in command and "-json" in command
    assert flag(command, "-rate") == str(scheduler.records["naabu"].rate)            # débit accordé par l'ordonnanceur
    assert tools.silent["naabu"] is True
    assert lines(tmp_path / "12_ports.txt") == ["www.example.com:443", "www.example.com:8080"]
    assert "evil.net" not in read(tmp_path / "12_naabu.jsonl") and "evil.net" not in read(tmp_path / "12_ports.txt")
    assert any(r.startswith("naabu\tapi.evil.net\t") for r in lines(tmp_path / "rejected_scope.tsv"))
    assert scheduler.records["naabu"].count == 2


def test_naabu_ports_option_and_off_switch(tmp_path, monkeypatch):
    _, _, tools = run_dag(tmp_path, monkeypatch, ports="80,8080-8090")
    assert flag(tools.of("naabu")[0], "-p") == "80,8080-8090" and "-top-ports" not in tools.of("naabu")[0]
    (tmp_path / "full").mkdir()
    scheduler, _, tools = run_dag(tmp_path / "full", monkeypatch, ports="full")       # refusé même si la CLI était contournée
    assert statuses(scheduler)["naabu"] is Status.FAILED and "naabu" not in tools.calls
    assert "--naabu-allow-full" in scheduler.records["naabu"].note
    assert statuses(scheduler)["httpx_ports"] is Status.SKIPPED
    (tmp_path / "ok").mkdir()
    _, _, tools = run_dag(tmp_path / "ok", monkeypatch, ports="full", naabu_allow_full=True)
    assert flag(tools.of("naabu")[0], "-top-ports") == "full"
    (tmp_path / "off").mkdir()
    scheduler, _, tools = run_dag(tmp_path / "off", monkeypatch, naabu=False)
    assert statuses(scheduler)["naabu"] is Status.SKIPPED and "naabu" not in tools.calls
    assert statuses(scheduler)["httpx_ports"] is Status.SKIPPED and "httpx ports" not in [l for l, _ in tools.commands]


def test_missing_naabu_disables_ports_modules_and_the_pipeline_continues(tmp_path, monkeypatch):
    scheduler, _, tools = run_dag(tmp_path, monkeypatch, missing={"naabu"}, nuclei=True)
    st = statuses(scheduler)
    assert st["naabu"] is Status.DISABLED and st["httpx_ports"] is Status.SKIPPED and st["nuclei_ports"] is Status.SKIPPED
    assert st["httpx2"] is Status.DONE and st["arjun"] is Status.DONE and st["nuclei2"] is Status.DONE
    assert not scheduler.failed and PORT_URL not in "\n".join(lines(tmp_path / "urls_all_final.txt"))


def test_naabu_needs_resolved_hosts(tmp_path, monkeypatch):
    scheduler, _, tools = run_dag(tmp_path, monkeypatch, missing={"dnsx"})
    assert statuses(scheduler)["naabu"] is Status.SKIPPED and "naabu" not in tools.calls      # jamais d'hôte non confirmé
    assert "dnsx" in scheduler.records["naabu"].note


def test_httpx_ports_excludes_80_and_443_and_lists_live_services(tmp_path, monkeypatch):
    tools = FakeTools(open_ports=(80, 443, 8080, 8443), codes={f"{W}:8080": 200, f"{W}:8443": 404})
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, tools=tools)
    assert lines(tmp_path / "13_httpx_ports_input.txt") == ["www.example.com:8080", "www.example.com:8443"]
    (command,) = tools.of("httpx ports")
    assert flag(command, "-l") == str(tmp_path / "13_httpx_ports_input.txt") and flag(command, "-rate-limit") == str(scheduler.records["httpx_ports"].rate)
    assert flag(command, "-o") == str(tmp_path / "13_httpx_ports.jsonl")
    assert len(lines(tmp_path / "13_httpx_ports.jsonl")) == 2
    assert lines(tmp_path / "urls_live_ports.txt") == [f"{W}:8080"]                    # 404 : pas vivant
    assert scheduler.records["httpx_ports"].count == 2


def test_httpx_ports_skips_when_only_default_web_ports_are_open(tmp_path, monkeypatch):
    scheduler, _, tools = run_dag(tmp_path, monkeypatch, tools=FakeTools(open_ports=(80, 443)))
    assert statuses(scheduler)["httpx_ports"] is Status.SKIPPED and "80/443" in scheduler.records["httpx_ports"].note
    assert "httpx ports" not in [l for l, _ in tools.commands] and not (tmp_path / "urls_live_ports.txt").exists()
    (tmp_path / "off").mkdir()
    scheduler, _, tools = run_dag(tmp_path / "off", monkeypatch, httpx_ports=False)
    assert statuses(scheduler)["httpx_ports"] is Status.SKIPPED and "option" in scheduler.records["httpx_ports"].note


def test_port_services_join_the_final_lists_the_tree_and_the_merge_replay(tmp_path, monkeypatch):
    tools = FakeTools(codes={PORT_URL: 200})
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, tools=tools)
    assert statuses(scheduler)["httpx2"] is Status.DONE and scheduler.records["httpx2"].start >= scheduler.records["httpx_ports"].end - 1e-3
    for name in ("urls_200_final.txt", "urls_live_final.txt"):
        assert PORT_URL in lines(tmp_path / name), name
    assert any(l.startswith(PORT_URL + " [200]") for l in lines(tmp_path / "urls_all_final.txt"))
    assert ":8080" in read(tmp_path / "urls_tree.html")
    assert PORT_URL not in read(tmp_path / "all_urls.txt")                           # la carte reste celle du crawl
    finals = {n: sorted(lines(tmp_path / n)) for n in ("urls_all_final.txt", "urls_200_final.txt", "urls_live_final.txt")}
    for name in (*finals, "urls_tree.html"):
        (tmp_path / name).unlink()
    write_config(tmp_path)
    merge_folder(tmp_path)                                                            # `recon_mano merge` reprend les services
    assert {n: sorted(lines(tmp_path / n)) for n in finals} == finals
    assert ":8080" in read(tmp_path / "urls_tree.html")


def test_port_services_reach_the_finals_even_when_the_map_is_empty(tmp_path, monkeypatch):
    tools = FakeTools(all_404=True, codes={PORT_URL: 200})
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, tools=tools)
    st = statuses(scheduler)
    assert st["katana"] is Status.SKIPPED and "katana" not in tools.calls            # rien de vivant sur 80/443
    assert st["httpx2"] is Status.DONE and lines(tmp_path / "urls_live_final.txt") == [PORT_URL]
    assert lines(tmp_path / "all_urls.txt") == [] and st["tree"] is Status.DONE


def test_port_services_out_of_scope_never_reach_the_finals(tmp_path, monkeypatch):
    tools = FakeTools(extra_ports=[("api.evil.net", 8081)], codes={PORT_URL: 200})
    run_dag(tmp_path, monkeypatch, tools=tools)
    for path in tmp_path.iterdir():
        if path.is_file() and path.name != "rejected_scope.tsv":
            assert "evil.net" not in path.read_text(encoding="utf-8", errors="replace"), path.name


def test_nuclei_ports_only_with_n_and_with_pass_one_settings(tmp_path, monkeypatch):
    scheduler, _, tools = run_dag(tmp_path, monkeypatch)
    assert statuses(scheduler)["nuclei_ports"] is Status.SKIPPED and "option" in scheduler.records["nuclei_ports"].note
    assert "nuclei" not in tools.calls and not (tmp_path / "nuclei_ports.jsonl").exists()
    assert not (tmp_path / "07_nuclei_ports_input.txt").exists() and not (tmp_path / "nuclei.txt").exists()

    (tmp_path / "n").mkdir()
    scheduler, ctx, tools = run_dag(tmp_path / "n", monkeypatch, tools=FakeTools(codes={PORT_URL: 200}), nuclei=True)
    assert statuses(scheduler)["nuclei_ports"] is Status.DONE
    (command,) = tools.of("nuclei ports")
    assert flag(command, "-l") == str(tmp_path / "n" / "07_nuclei_ports_input.txt")
    assert lines(tmp_path / "n" / "07_nuclei_ports_input.txt") == [PORT_URL]          # racine scheme://hôte:port
    assert "-as" in command and "-dast" not in command and flag(command, "-etags") == "fuzz,dos,intrusive"
    assert flag(command, "-severity") == "medium,high,critical"
    assert flag(command, "-rate-limit") == str(scheduler.records["nuclei_ports"].rate) == "50"
    assert flag(command, "-o").endswith("nuclei_ports.jsonl.1.part") and not list((tmp_path / "n").glob("*.part"))
    assert [json.loads(l)["matched-at"] for l in lines(tmp_path / "n" / "nuclei_ports.jsonl")] == [PORT_URL]
    counts = finalize_nuclei(ctx)
    assert f"[medium] fake-medium {PORT_URL}" in lines(tmp_path / "n" / "nuclei.txt")  # repris dans la vue fusionnée
    assert counts["medium"] == 2                                                       # passe 1 + services hors 80/443
    assert scheduler.records["nuclei_ports"].network


def test_nuclei_ports_follows_nuclei_passes(tmp_path, monkeypatch):
    scheduler, ctx, tools = run_dag(tmp_path, monkeypatch, tools=FakeTools(codes={PORT_URL: 200}), nuclei=True, nuclei_passes="2")
    assert statuses(scheduler)["nuclei_ports"] is Status.SKIPPED and "nuclei ports" not in [l for l, _ in tools.commands]
    assert statuses(scheduler)["nuclei2"] is Status.DONE
    (tmp_path / "x").mkdir()
    scheduler, _, _ = run_dag(tmp_path / "x", monkeypatch, tools=FakeTools(codes={PORT_URL: 200}), nuclei=True, nuclei_passes="1")
    assert statuses(scheduler)["nuclei_ports"] is Status.DONE and statuses(scheduler)["nuclei2"] is Status.SKIPPED


def test_stale_nuclei_ports_file_is_ignored_by_the_view(tmp_path, monkeypatch):
    stale = json.dumps({"template-id": "stale", "info": {"severity": "critical"}, "matched-at": "https://old:8443"})
    (tmp_path / "nuclei_ports.jsonl").write_text(stale + "\n", encoding="utf-8")
    scheduler, ctx, _ = run_dag(tmp_path, monkeypatch, nuclei=True, naabu=False)
    assert statuses(scheduler)["nuclei_ports"] is Status.SKIPPED
    counts = finalize_nuclei(ctx)
    assert "critical" not in counts and "stale" not in read(tmp_path / "nuclei.txt")


def test_port_scan_and_budget_never_exceed_max_rps(tmp_path, monkeypatch):
    scheduler, _, tools = run_dag(tmp_path, monkeypatch, tools=FakeTools(delays={"katana": 0.3, "naabu": 0.2}), max_rps=40)
    rec = scheduler.records["naabu"]
    assert rec.rate <= 40 and rec.requested_rate == 100
    assert flag(tools.of("naabu")[0], "-rate") == str(rec.rate)
    assert flag(tools.of("arjun")[0], "--rate-limit") == str(scheduler.records["arjun"].rate) and scheduler.records["arjun"].rate <= 40
    # Jamais plus que --max-rps en même temps.
    spans = [(r.start, r.end, r.rate) for r in scheduler.records.values() if r.rate]
    for start, _, _ in spans:
        assert sum(rate for s, e, rate in spans if s <= start < e) <= 40


# --------------------------------------------------------------------------- #
# arjun
# --------------------------------------------------------------------------- #

MANY = [f"{W}/zone{i}/list" for i in range(40)] + [f"{W}/api/users", f"{W}/admin/panel"]


def test_arjun_is_capped_prioritised_and_uses_the_granted_rate(tmp_path, monkeypatch):
    tools = FakeTools(gau_urls=MANY, codes={u: 200 for u in MANY})
    scheduler, ctx, _ = run_dag(tmp_path, monkeypatch, tools=tools, arjun_max=5)
    (inputs,) = tools.arjun_inputs
    assert len(inputs) == 5 and lines(tmp_path / "14_arjun_input.txt") == inputs
    flags = [signatures.is_priority(u) for u in inputs]
    assert any(flags) and flags == sorted(flags, reverse=True)                        # prioritaires d'abord
    assert {f"{W}/api/users", f"{W}/admin/panel"} <= set(inputs)
    assert not any(signatures.is_static(u) for u in inputs)
    (command,) = tools.of("arjun")
    assert flag(command, "--rate-limit") == str(scheduler.records["arjun"].rate) == "20"
    assert flag(command, "-oJ") == str(tmp_path / "14_arjun.json") and flag(command, "-m") == "GET"
    assert "--stable" not in command and tools.silent["arjun"] is False
    assert scheduler.records["arjun"].network and "5 URLs testées" in scheduler.records["arjun"].note


def test_arjun_default_cap_is_thirty(tmp_path, monkeypatch):
    tools = FakeTools(gau_urls=MANY, codes={u: 200 for u in MANY})
    run_dag(tmp_path, monkeypatch, tools=tools, archive_dedupe=False)
    (inputs,) = tools.arjun_inputs
    assert len(inputs) == 30 == MODULE_DEFAULTS["arjun"].params["max_urls"]


def test_arjun_param_urls_are_built_scoped_and_written(tmp_path, monkeypatch):
    gau = [f"{W}/search?q=a", f"{W}/api/users"]
    tools = FakeTools(gau_urls=gau, codes={u: 200 for u in gau}, arjun_hits={f"{W}/search?q=a", f"{W}/api/users"})
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, tools=tools)
    params_file = lines(tmp_path / "14_arjun_params.txt")
    assert f"{W}/search?q=a&debug=1" in params_file and f"{W}/api/users?debug=1" in params_file   # paramètres existants conservés
    assert all(u.startswith(W) for u in params_file)
    assert json.loads(read(tmp_path / "14_arjun.json"))[f"{W}/api/users"]["params"] == ["debug"]


def test_arjun_without_n_is_a_surface_deliverable_and_nuclei_never_runs(tmp_path, monkeypatch):
    scheduler, _, tools = run_dag(tmp_path, monkeypatch)
    assert statuses(scheduler)["arjun"] is Status.DONE and lines(tmp_path / "14_arjun_params.txt")
    assert "nuclei" not in tools.calls and statuses(scheduler)["nuclei2"] is Status.SKIPPED


def test_nuclei2_adds_arjun_params_to_its_dast_list_only_with_n(tmp_path, monkeypatch):
    gau = [f"{W}/search?q=a", f"{W}/search?q=b", f"{W}/search?q=c", f"{W}/api/users"]
    tools = FakeTools(gau_urls=gau, codes={u: 200 for u in gau})
    scheduler, ctx, tools = run_dag(tmp_path, monkeypatch, tools=tools, nuclei=True, nuclei_k=1)
    assert scheduler.records["nuclei2"].start >= scheduler.records["arjun"].end - 1e-3      # nuclei #2 attend arjun
    dast = lines(tmp_path / "07_nuclei2_params.txt")
    arjun_urls = lines(tmp_path / "14_arjun_params.txt")
    assert arjun_urls and set(arjun_urls) <= set(dast)
    reps_with_params = [u for u in lines(tmp_path / "07_nuclei2_input.txt") if signatures.has_params(u)]
    assert dast[:len(reps_with_params)] == reps_with_params                                  # ajoutées APRÈS la réduction par signature
    assert len(dast) == len(set(dast))
    (dast_cmd,) = tools.of("nuclei #2 DAST")
    assert flag(dast_cmd, "-l") == str(tmp_path / "07_nuclei2_params.txt") and "-dast" in dast_cmd

    (tmp_path / "off").mkdir()
    scheduler, _, tools = run_dag(tmp_path / "off", monkeypatch, tools=FakeTools(gau_urls=gau, codes={u: 200 for u in gau}),
                                  nuclei=True, nuclei_k=1, arjun=False)
    assert statuses(scheduler)["arjun"] is Status.SKIPPED and statuses(scheduler)["nuclei2"] is Status.DONE
    assert not any("debug=1" in u for u in lines(tmp_path / "off" / "07_nuclei2_params.txt"))


def test_stale_arjun_params_never_feed_nuclei2(tmp_path, monkeypatch):
    (tmp_path / "14_arjun_params.txt").write_text(f"{W}/stale?injected=1\n", encoding="utf-8")
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, nuclei=True, arjun=False)
    assert "injected" not in read(tmp_path / "07_nuclei2_params.txt")


def test_arjun_params_outside_the_scope_are_dropped_before_nuclei(tmp_path, monkeypatch):
    # Un arjun mal élevé (ou un fichier trafiqué) ne peut pas faire sortir nuclei du périmètre.
    import recon_mano.surface as surface_module
    monkeypatch.setattr(surface_module, "arjun_param_urls", lambda found: ["https://evil.net/x?a=1"] + [f"{W}/ok?a=1"])
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, nuclei=True)
    assert "evil.net" not in read(tmp_path / "14_arjun_params.txt") and "evil.net" not in read(tmp_path / "07_nuclei2_params.txt")
    assert any(r.startswith("arjun\tevil.net\t") for r in lines(tmp_path / "rejected_scope.tsv"))


def test_arjun_off_missing_or_nothing_to_test(tmp_path, monkeypatch):
    scheduler, _, tools = run_dag(tmp_path, monkeypatch, arjun=False)
    assert statuses(scheduler)["arjun"] is Status.SKIPPED and "arjun" not in tools.calls
    (tmp_path / "m").mkdir()
    scheduler, _, tools = run_dag(tmp_path / "m", monkeypatch, missing={"arjun"}, nuclei=True)
    assert statuses(scheduler)["arjun"] is Status.DISABLED and statuses(scheduler)["nuclei2"] is Status.DONE
    (tmp_path / "z").mkdir()
    scheduler, _, tools = run_dag(tmp_path / "z", monkeypatch, tools=FakeTools(all_404=True))
    assert statuses(scheduler)["arjun"] is Status.SKIPPED and "arjun" not in tools.calls
    (tmp_path / "s").mkdir()
    _, _, tools = run_dag(tmp_path / "s", monkeypatch, arjun_stable=True, arjun_threads=3)
    assert "--stable" in tools.of("arjun")[0] and flag(tools.of("arjun")[0], "-t") == "3"


# --------------------------------------------------------------------------- #
# Périmètre, CLI, nettoyage
# --------------------------------------------------------------------------- #


def test_nothing_new_leaves_the_scope(tmp_path, monkeypatch):
    tools = FakeTools(extra_ports=[("x.evil.net", 8080), ("y.other.org", 9000)])
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, tools=tools, nuclei=True)
    assert not scheduler.failed
    for path in tmp_path.iterdir():
        if path.is_file() and path.name != "rejected_scope.tsv":
            text = path.read_text(encoding="utf-8", errors="replace")
            for outside in ("evil.net", "other.org", "thirdparty.io"):
                assert outside not in text, f"{outside} dans {path.name}"


def test_cli_rejects_forbidden_port_specs_and_documents_the_new_options(tmp_path):
    runner_ = CliRunner()
    for bad in (["--ports", "full"], ["--ports", "1-65535"], ["--ports", "abc"], ["--arjun-max", "0"], ["--takeover-concurrency", "0"]):
        result = runner_.invoke(app(), ["example.com", str(tmp_path / "out"), "-y", *bad])
        assert result.exit_code == 2, bad
    p = params()
    for name in ("katana_store", "jsluice", "secrets", "takeover", "naabu", "httpx_ports", "arjun"):
        assert p[name].default is True and p[name].secondary_opts, name
        assert f"--no-{name.replace('_', '-')}" in p[name].secondary_opts, name
    assert p["naabu_allow_full"].default is False and p["arjun_stable"].default is False
    assert (p["ports"].default, p["arjun_max"].default, p["takeover_concurrency"].default) == ("top-1000", 30, 5)
    assert (p["naabu_timeout"].default, p["arjun_timeout"].default, p["takeover_timeout"].default) == (30, 30, 15)
    assert (p["jsluice_timeout"].default, p["secrets_timeout"].default) == (10, 10)
    assert (p["naabu_rate"].default, p["httpx_ports_rate"].default, p["arjun_rate"].default, p["takeover_rate"].default) == (100, 50, 20, 10)
    for name in ("katana_store", "jsluice", "secrets", "takeover", "naabu", "ports", "httpx_ports", "arjun", "arjun_max", "arjun_stable"):
        assert p[name].help and len(p[name].help) > 30, name
    help_text = CliRunner().invoke(app(), ["--help"]).output
    for option in ("--katana-store", "--jsluice", "--secrets", "--takeover", "--naabu", "--ports", "--httpx-ports", "--arjun", "--arjun-max"):
        assert option in help_text, option


def test_cli_end_to_end_options_flow_into_the_tools_and_the_deliverables(tmp_path, monkeypatch):
    tools = fake_environment(monkeypatch)
    out = tmp_path / "out"
    result = CliRunner().invoke(app(), [
        "example.com", str(out), "-y", "--ports", "80,8080-8090", "--arjun-max", "7", "--takeover-concurrency", "2",
        "--module-timeout", "naabu=5", "--arjun-rate", "12",
    ])
    assert result.exit_code == 0, result.output
    assert flag(tools.of("naabu")[0], "-p") == "80,8080-8090"
    assert flag(tools.of("subzy")[0], "--concurrency") == "2"
    assert flag(tools.of("arjun")[0], "--rate-limit") == "12"
    config = json.loads(read(out / "run_config.json"))
    for name in ("jsluice", "secrets", "takeover", "naabu", "httpx_ports", "arjun"):
        assert name in config["modules"], name
    assert "nuclei_ports" not in config["modules"] and config["timeouts"]["naabu"] == 300
    assert config["surface"] == {"ports": "80,8080-8090", "katana_store": True, "arjun_max": 7}
    # Livrables listés, secrets jamais affichés entiers.
    for name in ("10_secrets.txt", "11_takeover.txt", "12_ports.txt", "urls_live_ports.txt", "14_arjun_params.txt"):
        assert name in result.output, name
    assert FAKE_SECRET not in result.output and FAKE_KEY not in result.output
    stats = json.loads(read(out / "run_stats.json"))
    assert stats["workers"] == 6 and stats["max_rps"] == 150
    assert {m["name"] for m in stats["modules"]} == set(MODULE_DEFAULTS)


def test_cli_flags_turn_every_new_module_off(tmp_path, monkeypatch):
    tools = fake_environment(monkeypatch)
    out = tmp_path / "out"
    result = CliRunner().invoke(app(), [
        "example.com", str(out), "-y", "--no-katana-store", "--no-jsluice", "--no-secrets", "--no-takeover",
        "--no-naabu", "--no-httpx-ports", "--no-arjun",
    ])
    assert result.exit_code == 0, result.output
    assert not {"jsluice", "trufflehog", "gitleaks", "subzy", "naabu", "arjun"} & set(tools.calls)
    assert "dnsx cname" not in [label for label, _ in tools.commands]
    assert not {"-store-response", "-store-response-dir"} & set(tools.of("katana")[0])
    config = json.loads(read(out / "run_config.json"))
    assert not {"jsluice", "secrets", "takeover", "naabu", "httpx_ports", "arjun"} & set(config["modules"])
    assert not (out / "responses").exists()


def test_clean_removes_the_new_files_and_the_stored_responses(tmp_path):
    paths = build_paths(tmp_path)
    keys = ("jsluice", "jsluice_secrets", "secrets_jsonl", "secrets_txt", "dnsx_cname", "takeover_candidates", "takeover_jsonl",
            "takeover_txt", "naabu_jsonl", "ports", "httpx_ports_input", "httpx_ports_jsonl", "urls_live_ports",
            "nuclei_ports_input", "nuclei_ports_jsonl", "arjun_input", "arjun_json", "arjun_params")
    for key in keys:
        paths[key].write_text("x\n", encoding="utf-8")
    for temp in (".jsluice_files.tmp", ".secrets.tmp", ".subzy.tmp"):
        (tmp_path / temp).write_text("x\n", encoding="utf-8")
    (tmp_path / "responses" / "katana" / "h").mkdir(parents=True)
    (tmp_path / "responses" / "katana" / "h" / "f.txt").write_text("x", encoding="utf-8")
    (tmp_path / "keep.txt").write_text("x", encoding="utf-8")
    clean_artifacts(tmp_path)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["keep.txt"]


def test_check_lists_the_new_optional_binaries(monkeypatch, capsys):
    from recon_mano.cli import check_tools
    monkeypatch.setattr(runner, "resolve_httpx", lambda explicit=None: "/fake/httpx")
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: None if name in ("jsluice", "subzy", "arjun") else f"/fake/{name}")
    assert check_tools() == []                                            # jamais « requis »
    out = capsys.readouterr().out
    assert "jsluice (optionnel, module jsluice) introuvable" in out
    assert "subzy (optionnel, module takeover) introuvable" in out
    assert "arjun (optionnel, module arjun) introuvable" in out
    assert "naabu (optionnel, module naabu, httpx_ports, nuclei_ports) : /fake/naabu" in out
    assert "trufflehog (optionnel, module secrets)" in out and "gitleaks (optionnel, module secrets (repli de trufflehog))" in out


def test_direct_module_guards(tmp_path, monkeypatch):
    # Garde-fous appelés directement (hors ordonnanceur).
    ctx = make_ctx(tmp_path)
    ctx.state["subfinder_count"] = 1
    with pytest.raises(ModuleSkipped):
        run_naabu(ctx)                         # dnsx n'a rien produit : jamais d'hôte non confirmé
    with pytest.raises(ModuleSkipped):
        run_takeover(ctx)
    with pytest.raises(ModuleSkipped):
        run_httpx_ports(ctx)                   # naabu n'a pas tourné dans ce run
    ctx.state["hosts_file"] = tmp_path / "02_dnsx.txt"
    ctx.options.ports = "full"
    with pytest.raises(ModuleError, match="naabu-allow-full"):
        run_naabu(ctx)
