"""Phase 5 : réglages katana (débit, dédoublonnage par contenu, headless ciblé), presets, benchmark.

Faux outils uniquement, aucun réseau.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse

import pytest
from typer.testing import CliRunner

from recon_mano import modules as modules_mod
from recon_mano.config import (
    MODULE_DEFAULTS,
    NUCLEI_MODULES,
    PRESETS,
    parse_module_names,
    resolve_modules,
)
from recon_mano.liveness import (
    dedupe_seed_hosts,
    host_fingerprints,
    js_frameworks,
    js_heavy_hosts,
    row_fingerprint,
)
from recon_mano.modules import Options, build_modules, katana_command, plan_katana
from recon_mano.pipeline import Status

from .test_config import app, fake_environment, params
from .test_modules import FakeCrtsh, FakeTools, lines, run_dag, statuses
from .test_sources import flag

HOSTS4 = ["a.example.com", "b.example.com", "c.example.com", "d.example.com"]


def digest(body: str) -> str:
    return hashlib.sha256(body.encode()).hexdigest()


class HostTools(FakeTools):
    """FakeTools + ce que httpx sait des hôtes (`profiles`) et un katana headless qui peut échouer.

    `profiles` : URL exacte ou hôte (netloc) -> {"body", "length", "status", "tech"}. Les champs `tech`, `status_code`
    et `content_length` sont posés dès qu'un profil existe ; `hash` seulement si la commande a reçu `-hash`.
    """

    def __init__(self, profiles=None, headless_rc=0, **kwargs):
        kwargs.setdefault("hosts", HOSTS4)
        kwargs.setdefault("archive", [])
        super().__init__(**kwargs)
        self.profiles = profiles or {}
        self.headless_rc = headless_rc

    def __call__(self, command, label, **kwargs):
        rc, elapsed, stderr = super().__call__(command, label, **kwargs)
        tool = Path(command[0]).name
        if tool == "httpx" and self.profiles:
            out = Path(command[command.index("-o") + 1])
            rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines() if line.strip()]
            for row in rows:
                profile = self.profiles.get(row["url"]) or self.profiles.get(urlparse(row["url"]).netloc)
                if not profile:
                    continue
                row["tech"] = profile.get("tech", [])
                row["status_code"] = profile.get("status", 200)
                row["content_length"] = profile.get("length", 100)
                if "-hash" in command and "body" in profile:
                    row["hash"] = {"body_sha256": digest(profile["body"]), "header_sha256": digest("h")}
            out.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        if tool == "katana" and "-headless" in command and self.headless_rc:
            Path(command[command.index("-o") + 1]).write_text("", encoding="utf-8")
            return self.headless_rc, elapsed, "could not launch chrome\n"
        return rc, elapsed, stderr


def parked(**extra):
    return {"body": "parked page", "length": 500, "status": 200, **extra}


def host_dag(tmp_path, monkeypatch, tools, **opts):
    """run_dag sur les hôtes de HostTools seulement (crt.sh ne rend rien)."""
    return run_dag(tmp_path, monkeypatch, tools=tools, crtsh_fake=FakeCrtsh(script=[[]]), **opts)


def assert_all_done(scheduler):
    """Tout est terminé, sauf nuclei (opt-in, ignoré sans -n)."""
    st = {n: s for n, s in statuses(scheduler).items() if n not in NUCLEI_MODULES}
    assert all(s is Status.DONE for s in st.values()), st


def katana_commands(tools):
    return {label: command for label, command in tools.commands if label.startswith("katana")}


# --------------------------------------------------------------------------- #
# katana : débit
# --------------------------------------------------------------------------- #


def test_katana_rate_limit_option_and_default():
    assert MODULE_DEFAULTS["katana"].rate == 100 == params()["katana_rate_limit"].default
    assert Options(target="x.com").katana_rate_limit == 100
    assert {m.name: m.rate for m in build_modules(Options(target="x.com"))}["katana"] == 100
    assert params()["rate_limit"].default == 150                               # httpx garde 150
    assert {m.name: m.rate for m in build_modules(Options(target="x.com", katana_rate_limit=30))}["katana"] == 30


def test_katana_flag_carries_the_granted_rate(tmp_path, monkeypatch):
    scheduler, _, tools = run_dag(tmp_path, monkeypatch)
    assert scheduler.records["katana"].rate == 100
    assert flag(tools.of("katana")[0], "-rate-limit") == "100"
    (tmp_path / "small").mkdir()
    scheduler, _, tools = run_dag(tmp_path / "small", monkeypatch, max_rps=60)       # httpx prend 60 : katana plafonné
    assert flag(tools.of("katana")[0], "-rate-limit") == str(scheduler.records["katana"].rate) == "60"
    (tmp_path / "opt").mkdir()
    scheduler, _, tools = run_dag(tmp_path / "opt", monkeypatch, katana_rate_limit=25)
    assert flag(tools.of("katana")[0], "-rate-limit") == "25"


def test_without_n_katana_leaves_50_rps_to_the_other_network_modules(tmp_path, monkeypatch):
    tools = FakeTools(delays={"katana": 0.6, "naabu": 0.4, "dnsx": 0.0})
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, tools=tools)
    assert_all_done(scheduler)
    katana, naabu, takeover = (scheduler.records[n] for n in ("katana", "naabu", "takeover"))
    assert katana.rate == 100 and takeover.rate == 10 and naabu.rate == 40            # 100 + 10 + 40 = 150
    # naabu et takeover tournent PENDANT le crawl (avant : ils attendaient sa fin).
    for other in (naabu, takeover):
        assert other.start < katana.end and katana.start < other.end, other.name
    spans = [(r.start, r.end, r.rate) for r in scheduler.records.values() if r.rate]
    for start, _, _ in spans:
        assert sum(rate for s, e, rate in spans if s <= start < e) <= 150
    # …et httpx ports (50), qui suit naabu, démarre sans attendre la fin du crawl non plus.
    assert scheduler.records["httpx_ports"].start < katana.end


# --------------------------------------------------------------------------- #
# katana : dédoublonnage des hôtes par contenu
# --------------------------------------------------------------------------- #

FP = f"{digest('parked page')[:16]}/200/500"


def test_row_fingerprint_needs_a_hash_and_a_non_empty_body():
    row = {"url": "https://a", "status_code": 200, "content_length": 500, "hash": {"body_sha256": "ab" * 32}}
    assert row_fingerprint(row) == f"{'ab' * 8}/200/500"
    assert row_fingerprint({**row, "hash": {}}) == "" and row_fingerprint({k: v for k, v in row.items() if k != "hash"}) == ""
    assert row_fingerprint({**row, "content_length": 0}) == ""                        # page vide : rien à comparer
    assert row_fingerprint({**row, "status_code": 403}) != row_fingerprint(row)
    assert row_fingerprint({**row, "content_length": 501}) != row_fingerprint(row)


def test_root_row_is_preferred_over_the_first_row_of_the_host():
    def row(url, body):
        return {"url": url, "status_code": 200, "content_length": 10, "hash": {"body_sha256": digest(body)}}

    rows = [row("https://a.example.com/deep", "other"), row("https://a.example.com", "root")]
    seeds = ["https://a.example.com/deep", "https://a.example.com"]
    assert host_fingerprints(seeds, rows) == {"a.example.com": row_fingerprint(rows[1])}
    # sans racine : la première ligne de l'hôte
    assert host_fingerprints(seeds[:1], rows[:1]) == {"a.example.com": row_fingerprint(rows[0])}
    # le port compte : même hôte sur un autre port = un autre hôte
    assert set(host_fingerprints(["https://a.example.com:8443", "https://a.example.com"], [])) == {"a.example.com:8443", "a.example.com"}


def test_dedupe_groups_only_identical_fingerprints_and_keeps_the_first_host():
    def row(host, body="parked", status=200, length=50, hash_=True):
        r = {"url": f"https://{host}", "status_code": status, "content_length": length}
        if hash_:
            r["hash"] = {"body_sha256": digest(body)}
        return r

    rows = [row("a.x.com"), row("b.x.com"), row("c.x.com", status=403), row("d.x.com", length=51),
            row("e.x.com", body="other"), row("f.x.com", hash_=False), row("g.x.com", hash_=False), row("h.x.com")]
    seeds = [f"https://{h}.x.com{p}" for h in "abcdefgh" for p in ("", "/p")]
    seeds = [s.replace("https://a.x.com.x.com", "https://a.x.com") for s in seeds]
    kept, dropped = dedupe_seed_hosts(seeds, rows)
    assert [(k, d) for k, d, _ in dropped] == [("a.x.com", "b.x.com"), ("a.x.com", "h.x.com")]
    assert all(fp == row_fingerprint(rows[0]) for _, _, fp in dropped)
    # b et h disparaissent avec TOUS leurs seeds ; c (autre code), d (autre taille), e, f, g (sans hash) restent.
    assert {urlparse(u).netloc for u in kept} == {f"{c}.x.com" for c in "acdefg"}
    assert len(kept) == 12


def test_dedupe_writes_the_tsv_and_keeps_every_deliverable(tmp_path, monkeypatch):
    profiles = {"a.example.com": parked(), "b.example.com": parked(), "c.example.com": parked(length=501),
                "d.example.com": {"body": "unique", "length": 9, "status": 200}}
    tools = HostTools(profiles)
    scheduler, ctx, _ = host_dag(tmp_path, monkeypatch, tools, katana_headless="off")
    assert_all_done(scheduler)
    assert "-hash" in tools.of("httpx")[0] and flag(tools.of("httpx")[0], "-hash") == "sha256"
    assert "-hash" not in tools.of("httpx #2")[0]
    (command,) = katana_commands(tools).values()
    assert flag(command, "-list") == str(tmp_path / "06_katana_seeds.txt")
    assert {urlparse(u).netloc for u in lines(tmp_path / "06_katana_seeds.txt")} == {"a.example.com", "c.example.com", "d.example.com"}
    assert lines(tmp_path / "06_katana_dedup.tsv") == [f"a.example.com\tb.example.com\t{FP}"]
    assert "1 hôtes dédoublonnés" in scheduler.records["katana"].note
    # Les livrables gardent b.example.com (httpx a bien répondu) ; seul le crawl l'a ignoré.
    assert "https://b.example.com" in lines(tmp_path / "urls_live.txt")
    assert "https://b.example.com" in lines(tmp_path / "all_urls.txt") and "https://b.example.com" in lines(tmp_path / "urls_live_final.txt")
    assert "https://b.example.com/admin" not in lines(tmp_path / "06_katana.txt")
    assert "https://a.example.com/admin" in lines(tmp_path / "06_katana.txt")


def test_dedupe_off_changes_nothing(tmp_path, monkeypatch):
    profiles = {"a.example.com": parked(), "b.example.com": parked()}
    tools = HostTools(profiles)
    scheduler, _, _ = host_dag(tmp_path, monkeypatch, tools, katana_dedupe_hosts=False, katana_headless="off")
    assert all("-hash" not in command for _, command in tools.commands)             # httpx : commande d'avant
    (command,) = katana_commands(tools).values()
    assert flag(command, "-list") == str(tmp_path / "urls_live.txt")
    assert not (tmp_path / "06_katana_dedup.tsv").exists() and not (tmp_path / "06_katana_seeds.txt").exists()
    assert "https://b.example.com/admin" in lines(tmp_path / "06_katana.txt")


def test_dedupe_does_nothing_without_hashes(tmp_path, monkeypatch):
    scheduler, _, tools = host_dag(tmp_path, monkeypatch, HostTools(), katana_headless="off")   # aucun profil : pas de hash
    assert flag(katana_commands(tools)["katana"], "-list") == str(tmp_path / "urls_live.txt")
    assert not (tmp_path / "06_katana_dedup.tsv").exists()


def test_stale_dedup_files_are_removed(tmp_path, monkeypatch):
    (tmp_path / "06_katana_dedup.tsv").write_text("old\told\told\n", encoding="utf-8")
    (tmp_path / "06_katana_headless_seeds.txt").write_text("https://old\n", encoding="utf-8")
    host_dag(tmp_path, monkeypatch, HostTools(), katana_headless="off")
    assert not (tmp_path / "06_katana_dedup.tsv").exists() and not (tmp_path / "06_katana_headless_seeds.txt").exists()


# --------------------------------------------------------------------------- #
# katana : headless ciblé
# --------------------------------------------------------------------------- #

TECH = {
    "a.example.com": {"tech": ["Nginx:1.18.0", "REACT"]},          # casse ignorée
    "b.example.com": {"tech": ["Vue.js:3.2.1", "jQuery"]},         # version ignorée
    "c.example.com": {"tech": ["jQuery", "Bootstrap"]},
    "d.example.com": {"tech": []},
}


def test_js_framework_detection_is_case_insensitive_and_ignores_versions():
    assert js_frameworks(["Nginx", "React", "next.js:13", "ANGULARJS", "jQuery", "Svelte"]) == ["react", "next.js", "angularjs", "svelte"]
    assert js_frameworks(["Reactive", "Angular Material"]) == []                        # noms exacts, pas des sous-chaînes
    rows = [{"url": "https://a.x.com/p", "tech": ["Vue.js"]}, {"url": "https://a.x.com", "tech": ["Nuxt.js"]},
            {"url": "https://b.x.com", "tech": ["jQuery"]}]
    assert js_heavy_hosts(rows) == {"a.x.com": ["vue.js", "nuxt.js"]}


def test_katana_command_flags():
    base = dict(source=Path("in"), destination=Path("out"), depth=2, scope="rdn", js_crawl=False, rate_limit=100,
                concurrency=10, max_pages=3000, duration="10m", ignore_query=False, filter_similar=True)
    standard = katana_command(**base, store_dir=Path("store"))
    assert "-headless" in katana_command(**base, headless=True) and "-headless" not in standard
    headless = katana_command(**base, store_dir=Path("store"), headless=True, no_sandbox=True)
    assert "-headless" in headless and "-no-sandbox" in headless
    assert not {"-store-response", "-store-response-dir", "-xhr-extraction"} & set(headless)     # pas géré en headless / inutile
    assert "-no-sandbox" not in katana_command(**base, headless=True, no_sandbox=False)
    assert "-no-sandbox" not in standard and {"-store-response", "-store-response-dir"} <= set(standard)
    assert flag(standard, "-crawl-duration") == "10m"                                  # par seed
    assert standard[-2:] == ["-o", "out"]


def test_plan_splits_seeds_by_mode():
    rows = [{"url": f"https://{h}.x.com", "tech": t} for h, t in (("a", ["React"]), ("b", ["jQuery"]))]
    seeds = ["https://a.x.com", "https://a.x.com/p", "https://b.x.com"]
    auto = plan_katana(seeds, rows, False, "auto")
    assert (auto.headless, auto.standard) == (seeds[:2], seeds[2:]) and auto.frameworks == {"a.x.com": ["react"]}
    off = plan_katana(seeds, rows, False, "off")
    assert (off.headless, off.standard) == ([], seeds)
    every = plan_katana(seeds, rows, False, "all")
    assert (every.headless, every.standard) == (seeds, [])
    assert plan_katana(seeds, [], False, "auto").headless == []                        # sans lignes httpx : rien à détecter


def test_headless_runs_a_second_katana_on_js_hosts_and_merges_the_outputs(tmp_path, monkeypatch):
    monkeypatch.setattr(modules_mod, "running_as_root", lambda: True)
    scheduler, _, tools = host_dag(tmp_path, monkeypatch, HostTools(TECH), katana_dedupe_hosts=False, jsluice=False)
    assert statuses(scheduler)["katana"] is Status.DONE and not scheduler.failed
    commands = katana_commands(tools)
    standard, headless = commands["katana"], commands["katana headless"]
    assert {urlparse(u).netloc for u in lines(tmp_path / "06_katana_seeds.txt")} == {"c.example.com", "d.example.com"}
    assert {urlparse(u).netloc for u in lines(tmp_path / "06_katana_headless_seeds.txt")} == {"a.example.com", "b.example.com"}
    assert flag(standard, "-list") == str(tmp_path / "06_katana_seeds.txt") and "-headless" not in standard
    assert flag(standard, "-concurrency") == "10" and "-store-response" in standard
    assert flag(headless, "-list") == str(tmp_path / "06_katana_headless_seeds.txt")
    assert "-headless" in headless and "-no-sandbox" in headless                        # root simulé
    assert flag(headless, "-concurrency") == "3"
    assert "-store-response" not in headless
    assert flag(headless, "-rate-limit") == flag(standard, "-rate-limit") == "100"      # même débit accordé (runs séquentiels)
    assert tools.spans["katana"][1] <= tools.spans["katana headless"][0] + 1e-3
    crawled = lines(tmp_path / "06_katana.txt")
    assert {"https://a.example.com/admin", "https://b.example.com/admin", "https://c.example.com/admin"} <= set(crawled)
    assert not list(tmp_path.glob(".katana*")) and "2 hôtes headless" in scheduler.records["katana"].note
    # Les livrables gardent tous les hôtes.
    assert {urlparse(u).netloc for u in lines(tmp_path / "urls_live.txt")} == set(HOSTS4)


def test_headless_options_and_sandbox_modes(tmp_path, monkeypatch):
    monkeypatch.setattr(modules_mod, "running_as_root", lambda: False)
    tools = HostTools(TECH)
    host_dag(tmp_path, monkeypatch, tools, katana_dedupe_hosts=False, katana_headless_concurrency=1)
    headless = katana_commands(tools)["katana headless"]
    assert "-no-sandbox" not in headless and flag(headless, "-concurrency") == "1"      # auto : seulement en root
    (tmp_path / "on").mkdir()
    tools = HostTools(TECH)
    host_dag(tmp_path / "on", monkeypatch, tools, katana_dedupe_hosts=False, katana_no_sandbox="on")
    assert "-no-sandbox" in katana_commands(tools)["katana headless"]
    monkeypatch.setattr(modules_mod, "running_as_root", lambda: True)
    (tmp_path / "off").mkdir()
    tools = HostTools(TECH)
    host_dag(tmp_path / "off", monkeypatch, tools, katana_dedupe_hosts=False, katana_no_sandbox="off")
    assert "-no-sandbox" not in katana_commands(tools)["katana headless"]


def test_headless_failure_keeps_standard_results_and_the_module_succeeds(tmp_path, monkeypatch, capsys):
    tools = HostTools(TECH, headless_rc=1)
    scheduler, _, _ = host_dag(tmp_path, monkeypatch, tools, katana_dedupe_hosts=False, jsluice=False)
    out = capsys.readouterr().out
    rec = scheduler.records["katana"]
    assert rec.status is Status.DONE and "headless en échec (code 1)" in rec.note and not scheduler.failed
    assert "katana headless en échec" in out and "could not launch chrome" in out
    crawled = lines(tmp_path / "06_katana.txt")
    assert "https://c.example.com/admin" in crawled and "https://a.example.com/admin" not in crawled
    assert not (tmp_path / ".katana_headless.tmp").exists()
    assert statuses(scheduler)["merge_map"] is Status.DONE and statuses(scheduler)["httpx2"] is Status.DONE


def test_headless_off_is_one_standard_run_on_all_seeds(tmp_path, monkeypatch):
    tools = HostTools(TECH)
    host_dag(tmp_path, monkeypatch, tools, katana_dedupe_hosts=False, katana_headless="off")
    (command,) = katana_commands(tools).values()
    assert "-headless" not in command and flag(command, "-list") == str(tmp_path / "urls_live.txt")
    assert not (tmp_path / "06_katana_headless_seeds.txt").exists()


def test_headless_all_crawls_every_seed_in_the_browser(tmp_path, monkeypatch):
    tools = HostTools(TECH)
    scheduler, _, _ = host_dag(tmp_path, monkeypatch, tools, katana_dedupe_hosts=False, katana_headless="all")
    assert list(katana_commands(tools)) == ["katana headless"]                           # plus aucun seed pour le crawl standard
    assert {urlparse(u).netloc for u in lines(tmp_path / "06_katana_headless_seeds.txt")} == set(HOSTS4)
    assert statuses(scheduler)["katana"] is Status.DONE and not scheduler.failed
    assert len(lines(tmp_path / "06_katana.txt")) >= len(HOSTS4)


def test_headless_never_runs_without_httpx_rows(tmp_path, monkeypatch):
    # --skip-httpx : seeds = entrées brutes, aucune techno connue → crawl standard unique.
    tools = HostTools(TECH)
    host_dag(tmp_path, monkeypatch, tools, skip_httpx=True)
    assert list(katana_commands(tools)) == ["katana"]


def test_cli_validates_the_new_katana_options(tmp_path):
    for bad in (["--katana-headless", "maybe"], ["--katana-no-sandbox", "x"], ["--katana-rate-limit", "0"],
                ["--katana-headless-concurrency", "0"]):
        assert CliRunner().invoke(app(), ["example.com", str(tmp_path / "o"), "-y", *bad]).exit_code == 2, bad
    p = params()
    assert (p["katana_dedupe_hosts"].default, p["katana_headless"].default, p["katana_headless_concurrency"].default) == (True, "auto", 3)
    assert "--no-katana-dedupe-hosts" in p["katana_dedupe_hosts"].secondary_opts
    assert "PAR SEED" in p["katana_duration"].help


def test_cli_end_to_end_runs_the_new_katana_defaults(tmp_path, monkeypatch):
    tools = fake_environment(monkeypatch, tools=HostTools(TECH))
    out = tmp_path / "out"
    result = CliRunner().invoke(app(), ["example.com", str(out), "-y", "--no-katana-dedupe-hosts"])
    assert result.exit_code == 0, result.output
    assert flag(tools.of("katana")[0], "-rate-limit") == "100"
    config = json.loads((out / "run_config.json").read_text(encoding="utf-8"))
    assert config["preset"] == "full" and config["katana"]["headless"] == "auto" and config["katana"]["dedupe_hosts"] is False
    assert "katana headless" in [label for label, _ in tools.commands]


# --------------------------------------------------------------------------- #
# Presets
# --------------------------------------------------------------------------- #


def active(resolved):
    return [name for name, on in resolved.items() if on]


def test_presets_are_plain_lists_of_registry_names():
    assert set(PRESETS) == {"fast", "surface", "full"}
    for name, members in PRESETS.items():
        assert isinstance(members, list) and set(members) <= set(MODULE_DEFAULTS), name
    assert PRESETS["fast"] == ["subfinder", "subdomains", "dnsx", "httpx", "nuclei1"]
    assert not set(PRESETS["surface"]) & set(NUCLEI_MODULES)
    assert set(PRESETS["surface"]) | set(NUCLEI_MODULES) == set(MODULE_DEFAULTS)
    assert PRESETS["full"] == list(MODULE_DEFAULTS)


def test_resolve_fast_surface_full():
    assert active(resolve_modules("fast", set(), set(), False)) == ["subfinder", "subdomains", "dnsx", "httpx"]
    assert active(resolve_modules("fast", set(), set(), True)) == ["subfinder", "subdomains", "dnsx", "httpx", "nuclei1"]
    surface = resolve_modules("surface", set(), set(), False)
    assert active(surface) == PRESETS["surface"]
    assert active(resolve_modules("surface", set(), set(), True)) == PRESETS["surface"]      # -n n'ajoute aucun nuclei
    assert active(resolve_modules("full", set(), set(), False)) == [n for n in MODULE_DEFAULTS if n not in NUCLEI_MODULES]
    assert active(resolve_modules("full", set(), set(), True)) == list(MODULE_DEFAULTS)
    assert list(surface) == list(MODULE_DEFAULTS)                                            # toujours tous les modules, dans l'ordre


def test_precedence_flag_over_enable_disable_over_preset():
    assert resolve_modules("full", set(), {"gau"}, False)["gau"] is False                     # disable > preset
    assert resolve_modules("fast", {"katana"}, set(), False)["katana"] is True                # enable > preset
    assert resolve_modules("full", set(), {"gau"}, False, {"gau": True})["gau"] is True       # flag > disable
    assert resolve_modules("full", {"gau"}, set(), False, {"gau": False})["gau"] is False     # flag > enable
    assert resolve_modules("fast", set(), set(), False, {"katana": True})["katana"] is True   # flag > preset
    assert resolve_modules("full", set(), set(), False, {"amass": False})["amass"] is False


def test_nuclei_family_needs_dash_n_explicitly_and_is_never_silently_ignored():
    for name in NUCLEI_MODULES:
        with pytest.raises(ValueError, match="-n"):
            resolve_modules("full", {name}, set(), False)
        with pytest.raises(ValueError, match="-n"):
            resolve_modules("surface", {name}, set(), False)
        with pytest.raises(ValueError, match="-n"):
            resolve_modules("full", set(), set(), False, {name: True})
    resolved = resolve_modules("surface", {"nuclei2"}, set(), True)                          # enable explicite + -n : possible
    assert resolved["nuclei2"] is True and resolved["nuclei1"] is False
    assert resolve_modules("full", set(), {"nuclei1", "nuclei2", "nuclei_ports"}, True)["nuclei2"] is False
    assert resolve_modules("full", set(), set(), False)["nuclei1"] is False                   # listé par le preset, éteint sans -n : pas une erreur


def test_unknown_names_and_conflicts():
    with pytest.raises(ValueError, match="preset inconnu"):
        resolve_modules("turbo", set(), set(), False)
    with pytest.raises(ValueError, match="bogus"):
        resolve_modules("full", {"bogus"}, set(), False)
    with pytest.raises(ValueError, match="bogus"):
        resolve_modules("full", set(), {"bogus"}, False)
    with pytest.raises(ValueError, match="bogus"):
        resolve_modules("full", set(), set(), False, {"bogus": True})
    with pytest.raises(ValueError, match="ET"):
        resolve_modules("full", {"gau"}, {"gau"}, False)
    assert parse_module_names("Gau, amass waybackurls", "--enable") == {"gau", "amass", "waybackurls"}
    assert parse_module_names("", "--enable") == set()
    with pytest.raises(ValueError, match="--disable.*bogus"):
        parse_module_names("gau,bogus", "--disable")


def test_plumbing_modules_follow_their_consumers():
    resolved = resolve_modules("fast", {"httpx2"}, set(), False)
    assert resolved["httpx2"] and resolved["merge_map"] and resolved["subdomains"]           # merge_map activé d'office
    with pytest.raises(ValueError, match="subdomains.*dnsx"):
        resolve_modules("fast", set(), {"subdomains"}, False)
    with pytest.raises(ValueError, match="merge_map.*httpx2"):
        resolve_modules("full", set(), {"merge_map"}, False)
    with pytest.raises(ValueError, match="subdomains"):
        resolve_modules("full", set(), set(), False, {"subdomains": False})
    # plus aucun consommateur : la plomberie peut être éteinte
    assert resolve_modules("fast", set(), {"subdomains", "dnsx", "httpx"}, False)["subdomains"] is False


def test_fast_preset_runs_end_to_end_without_deadlock(tmp_path, monkeypatch):
    (tmp_path / "03_urlfinder.txt").write_text("https://stale.example.com/old\n", encoding="utf-8")   # run précédent
    resolved = resolve_modules("fast", set(), set(), True)
    scheduler, _, tools = run_dag(tmp_path, monkeypatch, modules=resolved, nuclei=True)
    st = statuses(scheduler)
    ran = {n for n, s in st.items() if s is Status.DONE}
    assert ran == {"subfinder", "subdomains", "dnsx", "httpx", "nuclei1"}, st
    assert {s for n, s in st.items() if n not in ran} == {Status.SKIPPED}
    assert not scheduler.failed and "désactivé" in scheduler.records["katana"].note
    assert not {"katana", "urlfinder", "naabu", "amass", "arjun"} & set(tools.calls) and "nuclei" in tools.calls
    # urlfinder éteint : son fichier périmé n'entre pas dans l'entrée d'httpx.
    assert "stale.example.com" not in "\n".join(lines(tmp_path / "04_httpx_input.txt"))
    assert (tmp_path / "urls_live.txt").exists() and (tmp_path / "nuclei_pass1.jsonl").exists()
    assert tools.calls.count("httpx") == 1


def test_fast_without_n_runs_no_nuclei(tmp_path, monkeypatch):
    resolved = resolve_modules("fast", set(), set(), False)
    scheduler, _, tools = run_dag(tmp_path, monkeypatch, modules=resolved)
    assert "nuclei" not in tools.calls and statuses(scheduler)["httpx"] is Status.DONE and not scheduler.failed


def test_surface_preset_runs_the_whole_surface_but_no_nuclei_even_with_n(tmp_path, monkeypatch):
    resolved = resolve_modules("surface", set(), set(), True)
    scheduler, _, tools = run_dag(tmp_path, monkeypatch, modules=resolved, nuclei=False)     # la CLI passe nuclei=False ici
    st = statuses(scheduler)
    assert all(st[n] is Status.DONE for n in PRESETS["surface"]), st
    assert "nuclei" not in tools.calls and all(st[n] is Status.SKIPPED for n in NUCLEI_MODULES)


def test_options_modules_gate_individual_modules(tmp_path, monkeypatch):
    resolved = resolve_modules("full", set(), {"gau", "naabu", "katana"}, False)
    scheduler, _, tools = run_dag(tmp_path, monkeypatch, modules=resolved)
    st = statuses(scheduler)
    assert st["gau"] is Status.SKIPPED and st["naabu"] is Status.SKIPPED and st["katana"] is Status.SKIPPED
    assert st["httpx_ports"] is Status.SKIPPED and st["jsluice"] is Status.SKIPPED        # leurs données manquent : ignorés proprement
    assert st["httpx2"] is Status.DONE and not scheduler.failed
    assert not {"gau", "naabu", "katana"} & set(tools.calls)


# --------------------------------------------------------------------------- #
# Presets : CLI
# --------------------------------------------------------------------------- #


def invoke(tmp_path, *args):
    return CliRunner().invoke(app(), ["example.com", str(tmp_path / "out"), "-y", *args])


def test_cli_enable_disable_validation(tmp_path):
    for bad in (["--enable", "bogus"], ["--disable", "gau,bogus"], ["--enable", "nuclei2"], ["--enable", "nuclei1,nuclei_ports"],
                ["--disable", "subdomains"], ["--enable", "gau", "--disable", "gau"]):
        assert invoke(tmp_path, *bad).exit_code == 2, bad
    result = invoke(tmp_path, "--enable", "nuclei2")
    assert "nuclei2" in result.output and "-n" in result.output
    assert "bogus" in invoke(tmp_path, "--disable", "bogus").output


def test_cli_disable_and_precedence(tmp_path, monkeypatch):
    tools = fake_environment(monkeypatch)
    out = tmp_path / "out"
    result = CliRunner().invoke(app(), ["example.com", str(out), "-y", "--disable", "gau,waybackurls,amass", "--gau"])
    assert result.exit_code == 0, result.output
    config = json.loads((out / "run_config.json").read_text(encoding="utf-8"))
    assert "gau" in config["modules"]                                                       # --gau explicite > --disable
    assert not {"waybackurls", "amass"} & set(config["modules"])
    assert "gau" in tools.calls and "waybackurls" not in tools.calls and "amass" not in tools.calls


def test_cli_enable_nuclei_with_n_and_skip_aliases(tmp_path, monkeypatch):
    tools = fake_environment(monkeypatch)
    out = tmp_path / "out"
    result = CliRunner().invoke(app(), ["example.com", str(out), "-y", "-n", "--disable", "nuclei2,nuclei_ports", "--skip-katana"])
    assert result.exit_code == 0, result.output
    config = json.loads((out / "run_config.json").read_text(encoding="utf-8"))
    assert "nuclei1" in config["modules"] and not {"nuclei2", "nuclei_ports", "katana"} & set(config["modules"])
    assert "nuclei" in tools.calls and "katana" not in tools.calls
    assert config["nuclei"]["enabled"] is True


def test_cli_n_is_reported_as_useless_when_every_nuclei_module_is_disabled(tmp_path, monkeypatch):
    tools = fake_environment(monkeypatch)
    result = CliRunner().invoke(app(), ["example.com", str(tmp_path / "out"), "-y", "-n", "--disable", "nuclei1,nuclei2,nuclei_ports"])
    assert result.exit_code == 0 and "-n sans effet" in result.output
    assert "nuclei" not in tools.calls and all("-cdn" not in c for _, c in tools.commands)


# --------------------------------------------------------------------------- #
# Benchmark synthétique
# --------------------------------------------------------------------------- #


def test_bench_module_runs_both_modes_quickly_and_reports(tmp_path):
    from bench import bench_pipeline as bench

    durations = {"katana": 4, "nuclei1": 3, "naabu": 2, "amass": 2}
    seq = bench.run_scenario("séquentiel + -n", sequential=True, nuclei=True, scale=0.02, durations=durations, workdir=tmp_path / "s")
    par = bench.run_scenario("parallèle + -n", sequential=False, nuclei=True, scale=0.02, durations=durations, workdir=tmp_path / "p")
    assert all(m["status"] == "done" for m in par.modules) and all(m["status"] == "done" for m in seq.modules)
    assert par.wall < seq.wall
    assert par.overlaps("nuclei1", "katana") and not seq.overlaps("nuclei1", "katana")
    assert par.record("katana")["rate"] == 100 and par.record("nuclei1")["rate"] == 50
    text = bench.format_report([seq, par])
    assert "SIMULATION" in text and "nuclei #1 chevauche katana : OUI" in text and "x" in text
    assert bench.DURATIONS_MIN["katana"] == 40 and bench.DURATIONS_MIN["nuclei2"] == 15
