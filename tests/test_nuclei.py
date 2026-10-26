"""nuclei en deux passes : cibles, commandes, débits, chevauchement avec katana, vue nuclei.txt.

Tout passe par de faux outils (voir `FakeTools`) : aucun binaire n'est lancé.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from recon_mano import findings, runner, ui
from recon_mano.cli import clean_artifacts, main
from recon_mano.liveness import protected_hosts
from recon_mano.modules import (
    NUCLEI1_EXCLUDE_TAGS,
    NUCLEI2_EXCLUDE_TAGS,
    Options,
    build_modules,
    finalize_nuclei,
    nuclei_pass1_filters,
    resolve_nuclei_passes,
    run_nuclei1,
    run_nuclei2,
)
from recon_mano.pipeline import ModuleSkipped, Status, build_paths

from .test_modules import FakeTools, lines, make_ctx, run_dag, statuses


def patch_tools(monkeypatch, tools=None, missing=("gf",)):
    """Remplace run_command / which pour un appel direct d'un `run_nuclei*`."""
    tools = tools or FakeTools()
    monkeypatch.setattr(runner, "run_command", tools)
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: None if name in missing else f"/fake/{name}")
    return tools


def flag(command, name):
    return command[command.index(name) + 1]


def pass1_ctx(tmp_path, live, httpx_rows=(), rate=50, **opts):
    ctx = make_ctx(tmp_path, nuclei=True, **opts)
    ctx.rate = rate
    ctx.state.update(subfinder_count=1, httpx_ran=True)
    (tmp_path / "urls_live.txt").write_text("\n".join(live) + "\n", encoding="utf-8")
    (tmp_path / "05_httpx.jsonl").write_text("".join(json.dumps(r) + "\n" for r in httpx_rows), encoding="utf-8")
    return ctx


# --------------------------------------------------------------------------- #
# Options : -n, --nuclei-passes, --nuclei-targets
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("passes, targets, expected", [
    (None, None, "1,2"),
    ("1,2", None, "1,2"),
    ("1", None, "1"),
    ("2", None, "2"),
    (" 2 , 1 ", None, "1,2"),
    ("2,2", None, "2"),
    (None, "hosts", "1"),
    (None, "urls", "1,2"),
    ("2", "hosts", "2"),          # --nuclei-passes l'emporte
    ("1,2", "hosts", "1,2"),
    ("1", "urls", "1"),
])
def test_resolve_nuclei_passes(passes, targets, expected):
    assert resolve_nuclei_passes(passes, targets) == expected


@pytest.mark.parametrize("passes, targets", [("3", None), ("", None), ("a", None), ("1,3", None), (None, "bogus"), (None, "")])
def test_resolve_nuclei_passes_rejects_bad_values(passes, targets):
    with pytest.raises(ValueError):
        resolve_nuclei_passes(passes, targets)


def test_passes_select_the_enabled_modules():
    def enabled(**opts):
        return {m.name: m.enabled for m in build_modules(Options(target="example.com", **opts)) if m.name.startswith("nuclei")}

    assert enabled() == {"nuclei1": False, "nuclei2": False}                                   # sans -n : rien
    assert enabled(nuclei_passes="1,2") == {"nuclei1": False, "nuclei2": False}               # les passes seules n'activent rien
    assert enabled(nuclei=True) == {"nuclei1": True, "nuclei2": True}
    assert enabled(nuclei=True, nuclei_passes="1") == {"nuclei1": True, "nuclei2": False}
    assert enabled(nuclei=True, nuclei_passes="2") == {"nuclei1": False, "nuclei2": True}


def test_nuclei1_is_declared_before_katana_and_depends_on_httpx_not_httpx2():
    modules = {m.name: m for m in build_modules(Options(target="example.com", nuclei=True))}
    order = [m.name for m in build_modules(Options(target="example.com", nuclei=True))]
    assert order.index("nuclei1") < order.index("katana")
    assert modules["nuclei1"].deps == ["httpx"] and modules["nuclei2"].deps == ["httpx2"]
    assert modules["nuclei1"].rate == 50 and modules["nuclei2"].rate == 150
    assert "nuclei" not in modules                                                              # l'ancien module n'existe plus


def test_cli_validates_and_documents_the_options(tmp_path):
    import typer.main

    app = typer.Typer()
    app.command()(main)
    runner_ = CliRunner()
    out = str(tmp_path / "out")
    for bad in (["--nuclei-passes", "3"], ["--nuclei-targets", "bogus"], ["--nuclei-waf-factor", "0"],
                ["--nuclei-waf-factor", "1.5"], ["--nuclei-k", "0"]):
        result = runner_.invoke(app, ["example.com", out, *bad])
        assert result.exit_code == 2, bad
    result = runner_.invoke(app, ["example.com", out, "--nuclei-passes", "x"])
    assert "--nuclei-passes" in result.output

    params = {p.name: p for p in typer.main.get_command(app).params}
    assert params["nuclei_rate_limit"].default == 50 and params["nuclei2_rate_limit"].default == 150
    assert params["nuclei_waf_factor"].default == 0.3 and params["nuclei_k"].default == 2
    assert params["nuclei_priority"].default is True and params["nuclei_passes"].default is None
    assert params["nuclei"].default is False                                                    # opt-in strict
    for name in ("nuclei_passes", "nuclei_targets", "nuclei2_rate_limit", "nuclei_waf_factor", "nuclei_k", "nuclei_priority",
                 "nuclei_rate_limit"):
        assert params[name].help and len(params[name].help) > 20, name
    assert "--no-nuclei-priority" in params["nuclei_priority"].secondary_opts


def test_clean_removes_new_and_legacy_nuclei_files(tmp_path):
    names = ["07_nuclei_input.txt", "07_nuclei1_input.txt", "07_nuclei2_params.txt", "nuclei_pass1.jsonl", "nuclei_pass2.jsonl", "nuclei.txt"]
    for name in names:
        (tmp_path / name).write_text("x\n", encoding="utf-8")
    clean_artifacts(tmp_path)
    assert not [n for n in names if (tmp_path / n).exists()]


# --------------------------------------------------------------------------- #
# Sans -n : comportement inchangé
# --------------------------------------------------------------------------- #


def test_without_n_httpx_command_has_no_cdn_and_nothing_nuclei_runs(tmp_path, monkeypatch):
    scheduler, ctx, tools = run_dag(tmp_path, monkeypatch)
    httpx_commands = [c for label, c in tools.commands if label.startswith("httpx")]
    assert len(httpx_commands) == 2 and all("-cdn" not in c for c in httpx_commands)
    assert statuses(scheduler)["nuclei1"] is Status.SKIPPED and statuses(scheduler)["nuclei2"] is Status.SKIPPED
    assert "nuclei" not in tools.calls and "gf" not in tools.calls
    assert scheduler.records["katana"].rate == 150
    assert not [p.name for p in tmp_path.iterdir() if "nuclei" in p.name]
    for key in ("nuclei1_input", "nuclei2_input", "nuclei1_jsonl", "nuclei2_jsonl", "nuclei"):
        assert not build_paths(tmp_path)[key].exists()


def test_with_n_only_the_first_httpx_asks_for_cdn(tmp_path, monkeypatch):
    _, _, tools = run_dag(tmp_path, monkeypatch, nuclei=True)
    assert "-cdn" in tools.of("httpx")[0] and "-cdn" not in tools.of("httpx #2")[0]


def test_pass_2_only_does_not_need_cdn(tmp_path, monkeypatch):
    scheduler, _, tools = run_dag(tmp_path, monkeypatch, nuclei=True, nuclei_passes="2")
    assert "-cdn" not in tools.of("httpx")[0]
    assert statuses(scheduler)["nuclei1"] is Status.SKIPPED and statuses(scheduler)["nuclei2"] is Status.DONE
    assert scheduler.records["katana"].rate == 150                                              # nuclei1 absent : katana a tout


# --------------------------------------------------------------------------- #
# Passe 1
# --------------------------------------------------------------------------- #


def test_pass1_targets_are_host_port_roots_deduped_and_scoped(tmp_path, monkeypatch):
    tools = patch_tools(monkeypatch)
    ctx = pass1_ctx(tmp_path, [
        "https://www.example.com/a", "https://www.example.com/b?x=1", "https://WWW.example.com/z",
        "https://www.example.com:8443/c", "http://shop.example.com:8080/", "https://evil.net/x",
    ])
    run_nuclei1(ctx)
    # Un même hôte sur deux ports = deux cibles ; chemins retirés ; doublon retiré.
    assert lines(tmp_path / "07_nuclei1_input.txt") == [
        "https://www.example.com", "https://www.example.com:8443", "http://shop.example.com:8080",
    ]
    rejected = lines(tmp_path / "rejected_scope.tsv")
    assert any(r.startswith("nuclei1\tevil.net\t") for r in rejected)
    assert ctx.scope.rejected["nuclei1"] == 1
    # Aucun WAF : un seul lot, directement sur le fichier d'entrée, au débit accordé.
    (command,) = tools.of("nuclei #1")
    assert flag(command, "-l") == str(tmp_path / "07_nuclei1_input.txt")
    assert not (tmp_path / "07_nuclei1_input_waf.txt").exists() and not tools.of("nuclei #1 (WAF/CDN)")


def test_pass1_command_flags(tmp_path, monkeypatch):
    tools = patch_tools(monkeypatch)
    ctx = pass1_ctx(tmp_path, ["https://www.example.com/"], rate=37)
    run_nuclei1(ctx)
    (command,) = tools.of("nuclei #1")
    assert command[0] == "nuclei" and "-as" in command and "-dast" not in command
    assert flag(command, "-etags") == NUCLEI1_EXCLUDE_TAGS == "fuzz,dos,intrusive"
    assert flag(command, "-severity") == "medium,high,critical"
    assert flag(command, "-rate-limit") == "37"                       # débit ACCORDÉ par l'ordonnanceur
    assert flag(command, "-max-host-error") == "10" and flag(command, "-timeout") == "5"
    assert flag(command, "-concurrency") == "25" and flag(command, "-retries") == "1"
    assert "-jsonl" in command and flag(command, "-o").endswith("nuclei_pass1.jsonl.1.part")
    assert (tmp_path / "nuclei_pass1.jsonl").exists() and not list(tmp_path.glob("*.part"))


@pytest.mark.parametrize("mode", ["auto", "curated", "full"])
def test_pass1_filters_never_dast_always_etags(mode):
    filters = nuclei_pass1_filters(mode, "high,critical")
    assert "-dast" not in filters
    assert filters[filters.index("-etags") + 1] == "fuzz,dos,intrusive"
    assert filters[filters.index("-severity") + 1] == "high,critical"
    assert ("-as" in filters) == (mode == "auto")
    assert ("-tags" in filters) == (mode == "curated")
    if mode == "curated":
        assert filters[filters.index("-tags") + 1] == "cve,exposure,misconfig,takeover,default-login"


def test_pass1_waf_hosts_go_in_a_second_slower_batch(tmp_path, monkeypatch):
    tools = patch_tools(monkeypatch)
    rows = [
        {"url": "https://www.example.com", "cdn": False},
        {"url": "https://shop.example.com", "cdn": True, "cdn_name": "cloudflare", "cdn_type": "waf"},
        {"url": "https://static.example.com", "cdn": True, "cdn_name": "fastly", "cdn_type": "cdn"},
        {"url": "https://cloud.example.com", "cdn": True, "cdn_name": "aws", "cdn_type": "cloud"},   # simple hébergeur
        {"url": "https://old.example.com", "cdn": True, "cdn_name": "akamai"},                        # ancien httpx : sans type
    ]
    ctx = pass1_ctx(tmp_path, [r["url"] + "/" for r in rows], httpx_rows=rows, rate=50)
    result = run_nuclei1(ctx)

    (normal,) = tools.of("nuclei #1")
    (waf,) = tools.of("nuclei #1 (WAF/CDN)")
    assert lines(Path(flag(normal, "-l"))) == ["https://www.example.com", "https://cloud.example.com"]
    assert lines(Path(flag(waf, "-l"))) == ["https://shop.example.com", "https://static.example.com", "https://old.example.com"]
    assert flag(normal, "-rate-limit") == "50" and flag(waf, "-rate-limit") == "15"        # 50 × 0.3
    for command in (normal, waf):                                                          # mêmes templates
        assert command[command.index("-as"):command.index("-as") + 1] == ["-as"] and "-dast" not in command
    assert tools.spans["nuclei #1"][1] <= tools.spans["nuclei #1 (WAF/CDN)"][0]            # le lot WAF vient APRÈS
    assert lines(tmp_path / "07_nuclei1_input.txt")[0] == "https://www.example.com" and len(lines(tmp_path / "07_nuclei1_input.txt")) == 5
    assert result.count == 5 and "WAF" in result.note
    merged = [json.loads(l)["matched-at"] for l in lines(tmp_path / "nuclei_pass1.jsonl")]
    assert sorted(merged) == sorted(r["url"] for r in rows)


def test_pass1_waf_factor_and_floor(tmp_path, monkeypatch):
    rows = [{"url": "https://waf.example.com", "cdn": True, "cdn_name": "c", "cdn_type": "waf"}]
    tools = patch_tools(monkeypatch)
    run_nuclei1(pass1_ctx(tmp_path, ["https://waf.example.com/"], rows, rate=40, nuclei_waf_factor=0.5))
    assert flag(tools.of("nuclei #1 (WAF/CDN)")[0], "-rate-limit") == "20"
    assert not tools.of("nuclei #1")                                                       # tout est WAF : un seul lot

    tools = patch_tools(monkeypatch)
    run_nuclei1(pass1_ctx(tmp_path, ["https://waf.example.com/"], rows, rate=2, nuclei_waf_factor=0.3))
    assert flag(tools.of("nuclei #1 (WAF/CDN)")[0], "-rate-limit") == "1"                  # plancher : jamais 0


def test_pass1_skips_without_live_hosts_or_httpx(tmp_path, monkeypatch):
    patch_tools(monkeypatch)
    with pytest.raises(ModuleSkipped, match="Aucun hôte vivant"):
        run_nuclei1(pass1_ctx(tmp_path, ["https://evil.net/x"]))
    ctx = pass1_ctx(tmp_path, ["https://www.example.com/"])
    ctx.state["httpx_ran"] = False
    with pytest.raises(ModuleSkipped, match="httpx"):
        run_nuclei1(ctx)


def test_protected_hosts_parsing(tmp_path):
    rows = [
        {"url": "https://a.example.com", "cdn": True, "cdn_name": "cloudflare", "cdn_type": "waf"},
        {"url": "https://b.example.com:443", "cdn": True, "cdn_name": "fastly", "cdn_type": "cdn"},
        {"url": "https://c.example.com", "cdn": True, "cdn_name": "aws", "cdn_type": "cloud"},
        {"url": "https://d.example.com", "cdn": False},
        {"url": "https://e.example.com"},                                              # httpx lancé sans -cdn
        {"url": "https://f.example.com:8443", "cdn": True, "cdn_name": "akamai"},
        {"input": "g.example.com", "cdn": True, "cdn_name": "sucuri", "cdn_type": "waf"},
    ]
    f = tmp_path / "h.jsonl"
    f.write_text("".join(json.dumps(r) + "\n" for r in rows) + "pas du json\n", encoding="utf-8")
    result = protected_hosts(f)
    assert set(result) == {"a.example.com", "b.example.com", "f.example.com:8443", "g.example.com"}   # :443 normalisé
    assert result["a.example.com"] == "cloudflare (waf)" and result["f.example.com:8443"] == "akamai"
    assert protected_hosts(tmp_path / "absent.jsonl") == {}


# --------------------------------------------------------------------------- #
# Passe 2
# --------------------------------------------------------------------------- #

W = "https://www.example.com"
URLS = (
    [f"{W}/produit/{i}" for i in range(1, 6)]
    + [f"{W}/search?q=a", f"{W}/search?q=b", f"{W}/search?q=c"]
    + [f"{W}/admin/login", f"{W}/api/v1/users?id=3", f"{W}/static/app.js", f"{W}/logo.png", "https://evil.net/x?id=1"]
)


def pass2_ctx(tmp_path, urls=URLS, rate=150, final=True, **opts):
    ctx = make_ctx(tmp_path, nuclei=True, **opts)
    ctx.rate = rate
    ctx.state.update(subfinder_count=1, httpx_ran=True)
    if final:
        ctx.state["httpx2_ran"] = True
    name = "urls_live_final.txt" if final else "urls_live.txt"
    (tmp_path / name).write_text("\n".join(urls) + "\n", encoding="utf-8")
    return ctx


def test_pass2_inputs_reps_params_priority(tmp_path, monkeypatch):
    patch_tools(monkeypatch)
    run_nuclei2(pass2_ctx(tmp_path))
    reps = lines(tmp_path / "07_nuclei2_input.txt")
    # K=2 par signature, statiques et hors-scope exclus, ordre d'entrée conservé.
    assert reps == [f"{W}/produit/1", f"{W}/produit/2", f"{W}/search?q=a", f"{W}/search?q=b", f"{W}/admin/login", f"{W}/api/v1/users?id=3"]
    assert lines(tmp_path / "07_nuclei2_params.txt") == [f"{W}/search?q=a", f"{W}/search?q=b", f"{W}/api/v1/users?id=3"]
    # Sans gf : mots sensibles du chemin + noms de paramètres suspects (q, id).
    assert lines(tmp_path / "07_nuclei2_priority.txt") == [f"{W}/search?q=a", f"{W}/search?q=b", f"{W}/admin/login", f"{W}/api/v1/users?id=3"]
    assert any(r.startswith("nuclei2\tevil.net\t") for r in lines(tmp_path / "rejected_scope.tsv"))


def test_pass2_two_commands(tmp_path, monkeypatch):
    tools = patch_tools(monkeypatch)
    ctx = pass2_ctx(tmp_path, rate=120)
    result = run_nuclei2(ctx)

    (dast,) = tools.of("nuclei #2 DAST")
    assert "-dast" in dast and "-as" not in dast
    assert flag(dast, "-l") == str(tmp_path / "07_nuclei2_params.txt")
    assert flag(dast, "-severity") == "medium,high,critical"
    assert flag(dast, "-etags") == NUCLEI2_EXCLUDE_TAGS == "dos,intrusive"
    assert flag(dast, "-rate-limit") == "120" and "-jsonl" in dast

    (expo,) = tools.of("nuclei #2 exposition")
    assert flag(expo, "-tags") == "exposure,misconfig"
    assert "-severity" not in expo and "-dast" not in expo and "-as" not in expo      # tous les niveaux de sévérité
    assert flag(expo, "-etags") == "dos,intrusive"
    assert flag(expo, "-l") == str(tmp_path / "07_nuclei2_priority.txt")
    assert flag(expo, "-rate-limit") == "120"

    assert tools.spans["nuclei #2 DAST"][1] <= tools.spans["nuclei #2 exposition"][0]   # A puis B
    out = lines(tmp_path / "nuclei_pass2.jsonl")
    assert result.count == len(out) == 3 + 4                                           # 3 URLs DAST + 4 prioritaires
    assert all(isinstance(json.loads(l), dict) for l in out)
    assert not list(tmp_path.glob("*.part"))


def test_pass2_output_drops_truncated_json_lines(tmp_path, monkeypatch):
    patch_tools(monkeypatch, FakeTools(truncate_nuclei=True))
    result = run_nuclei2(pass2_ctx(tmp_path))
    out = lines(tmp_path / "nuclei_pass2.jsonl")
    assert out and all(isinstance(json.loads(l), dict) for l in out)                   # chaque ligne est du JSON valide
    assert result.count == len(out) == 7


def test_pass2_custom_severity_and_k(tmp_path, monkeypatch):
    tools = patch_tools(monkeypatch)
    run_nuclei2(pass2_ctx(tmp_path, nuclei_k=1, nuclei_severity="critical"))
    assert flag(tools.of("nuclei #2 DAST")[0], "-severity") == "critical"
    assert len(lines(tmp_path / "07_nuclei2_input.txt")) == 4                         # K=1 : produit, search, admin, api
    # Le run exposition reste sans filtre de sévérité.
    assert "-severity" not in tools.of("nuclei #2 exposition")[0]


def test_pass2_no_priority_option_skips_run_b(tmp_path, monkeypatch):
    tools = patch_tools(monkeypatch)
    run_nuclei2(pass2_ctx(tmp_path, nuclei_priority=False))
    assert tools.of("nuclei #2 DAST") and not tools.of("nuclei #2 exposition")
    assert not (tmp_path / "07_nuclei2_priority.txt").exists()
    assert "gf" not in tools.calls


def test_pass2_without_params_skips_dast_with_a_note(tmp_path, monkeypatch):
    tools = patch_tools(monkeypatch)
    ctx = pass2_ctx(tmp_path, urls=[f"{W}/admin/login", f"{W}/produit/1"])
    run_nuclei2(ctx)
    assert not tools.of("nuclei #2 DAST") and tools.of("nuclei #2 exposition")
    assert any("DAST ignoré" in line for line in ctx.lines)
    assert lines(tmp_path / "07_nuclei2_params.txt") == []


def test_pass2_nothing_to_run_is_skipped(tmp_path, monkeypatch):
    tools = patch_tools(monkeypatch)
    with pytest.raises(ModuleSkipped, match="rien à lancer"):
        run_nuclei2(pass2_ctx(tmp_path, urls=[f"{W}/produit/1", f"{W}/produit/2"]))
    assert "nuclei" not in tools.calls
    with pytest.raises(ModuleSkipped, match="non statique"):
        run_nuclei2(pass2_ctx(tmp_path, urls=[f"{W}/a.js", f"{W}/b.png"]))


def test_pass2_gf_matches_join_the_priority_list(tmp_path, monkeypatch):
    tools = patch_tools(monkeypatch, FakeTools(gf_hits={"xss": [f"{W}/produit/1"], "sqli": [f"{W}/search?q=b"]}), missing=())
    run_nuclei2(pass2_ctx(tmp_path))
    assert {c[1] for label, c in tools.commands if label.startswith("gf ")} == {"xss", "sqli"}      # seuls les motifs installés
    assert lines(tmp_path / "07_nuclei2_priority.txt") == [
        f"{W}/produit/1", f"{W}/search?q=b", f"{W}/admin/login", f"{W}/api/v1/users?id=3",   # gf + mots du chemin
    ]
    assert f"{W}/search?q=a" not in lines(tmp_path / "07_nuclei2_priority.txt")           # ?q= n'est plus un repli : gf fait foi


def test_pass2_falls_back_to_live_list_when_httpx2_did_not_run(tmp_path, monkeypatch):
    patch_tools(monkeypatch)
    run_nuclei2(pass2_ctx(tmp_path, urls=[f"{W}/admin/login", f"{W}/s?q=1"], final=False))
    assert lines(tmp_path / "07_nuclei2_input.txt") == [f"{W}/admin/login", f"{W}/s?q=1"]


# --------------------------------------------------------------------------- #
# Ordonnanceur : nuclei1 en parallèle de katana
# --------------------------------------------------------------------------- #


def test_nuclei1_runs_during_katana_and_shares_the_budget(tmp_path, monkeypatch):
    tools = FakeTools(delays={"katana": 0.4, "nuclei": 0.4})
    scheduler, ctx, _ = run_dag(tmp_path, monkeypatch, tools=tools, nuclei=True)
    assert all(s is Status.DONE for s in statuses(scheduler).values()), statuses(scheduler)
    httpx, n1, katana = (scheduler.records[n] for n in ("httpx", "nuclei1", "katana"))
    assert n1.start >= httpx.end - 1e-3                          # dès qu'httpx #1 a confirmé les hôtes…
    assert n1.start < katana.end and katana.start < n1.end       # …et pendant que katana crawle
    assert n1.start <= katana.start + 0.05                       # même tour d'ordonnanceur : nuclei1 passe d'abord
    # Budget : nuclei 50 d'abord, katana prend le reste ; jamais plus de --max-rps.
    assert n1.rate == 50 and katana.rate == 100 and n1.rate + katana.rate <= 150
    assert katana.requested_rate == 150
    # La passe 2 attend httpx #2 ; la 1 n'attend pas la fin du crawl.
    assert scheduler.records["nuclei2"].start >= scheduler.records["httpx2"].end - 1e-3
    # run_stats.json expose les décalages de départ qui prouvent le chevauchement.
    stats = {m["name"]: m for m in json.loads((tmp_path / "run_stats.json").read_text(encoding="utf-8"))["modules"]}
    assert stats["nuclei1"]["start"] < stats["katana"]["end"] and stats["katana"]["start"] < stats["nuclei1"]["end"]


def test_budget_with_small_max_rps(tmp_path, monkeypatch):
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, tools=FakeTools(delays={"katana": 0.3, "nuclei": 0.3}), nuclei=True, max_rps=60)
    n1, katana = scheduler.records["nuclei1"], scheduler.records["katana"]
    assert n1.rate == 50 and katana.rate == 10 and n1.rate + katana.rate <= 60


def test_summary_table_shows_start_offsets(capsys):
    rows = [
        ui.ModuleRow("katana", "katana", "K", "done", 10, 5.0, 100, "", 12.0),
        ui.ModuleRow("nuclei1", "nuclei #1", "N", "done", 3, 9.0, 50, "", 12.0),
        ui.ModuleRow("nuclei2", "nuclei #2", "N", "skipped", 0, 0.0, 0, "désactivé (option)", 40.0),
    ]
    ui.print_summary(rows, 30.0, 14.0)
    out = capsys.readouterr().out
    assert "début" in out and out.count("+12s") == 2
    assert "+40s" not in out                                         # un module ignoré n'a pas de début affiché


# --------------------------------------------------------------------------- #
# Fuite d'un katana périmé
# --------------------------------------------------------------------------- #


def test_stale_katana_file_is_ignored_when_katana_is_skipped(tmp_path, monkeypatch):
    (tmp_path / "06_katana.txt").write_text("https://stale.example.com/leak\n", encoding="utf-8")
    scheduler, _, tools = run_dag(tmp_path, monkeypatch, skip_katana=True)
    assert statuses(scheduler)["katana"] is Status.SKIPPED and "katana" not in tools.calls
    assert "stale.example.com" not in (tmp_path / "all_urls.txt").read_text(encoding="utf-8")
    assert "www.example.com" in (tmp_path / "all_urls.txt").read_text(encoding="utf-8")        # les seeds restent


def test_katana_file_is_used_when_katana_ran(tmp_path, monkeypatch):
    scheduler, _, _ = run_dag(tmp_path, monkeypatch)
    assert statuses(scheduler)["katana"] is Status.DONE
    assert "https://www.example.com/admin" in lines(tmp_path / "all_urls.txt")


# --------------------------------------------------------------------------- #
# nuclei.txt et décompte par sévérité
# --------------------------------------------------------------------------- #


def test_nuclei_txt_is_the_merged_sorted_view(tmp_path, monkeypatch):
    scheduler, ctx, _ = run_dag(tmp_path, monkeypatch, nuclei=True)
    counts = finalize_nuclei(ctx)
    view = lines(tmp_path / "nuclei.txt")
    assert view and all(l.startswith(("[medium] ", "[info] ")) for l in view)
    assert view[0] == "[medium] fake-medium https://www.example.com"               # passe 1
    assert view[1].startswith("[info] fake-info https://www.example.com")          # passe 2 (exposition), après le plus grave
    assert [l.split("]")[0] for l in view] == sorted((l.split("]")[0] for l in view), key=["[critical", "[high", "[medium", "[low", "[info"].index)
    assert counts == {"medium": 1, "info": len(view) - 1}


def test_findings_view_sorting_dedup_and_counts(tmp_path):
    def row(sev, tid, at):
        return json.dumps({"template-id": tid, "info": {"severity": sev}, "matched-at": at})

    p1, p2 = tmp_path / "p1.jsonl", tmp_path / "p2.jsonl"
    p1.write_text("\n".join([row("low", "b", "https://x/1"), row("critical", "z", "https://x/2"), row("weird", "w", "https://x/3"), "pas du json"]) + "\n", encoding="utf-8")
    p2.write_text("\n".join([row("critical", "z", "https://x/2"), row("high", "a", "https://x/4"), row("critical", "a", "https://x/5")]) + "\n", encoding="utf-8")
    counts = findings.write_view([p1, p2], tmp_path / "nuclei.txt")
    assert lines(tmp_path / "nuclei.txt") == [
        "[critical] a https://x/5", "[critical] z https://x/2", "[high] a https://x/4", "[low] b https://x/1", "[unknown] w https://x/3",
    ]
    assert counts == {"critical": 2, "high": 1, "low": 1, "unknown": 1}
    assert findings.severity_line({}) == "aucun finding"
    assert "2 critical" in findings.severity_line(counts) and "1 high" in findings.severity_line(counts)


def test_stale_pass_jsonl_is_ignored_by_the_view(tmp_path, monkeypatch):
    stale = json.dumps({"template-id": "stale", "info": {"severity": "critical"}, "matched-at": "https://old"})
    (tmp_path / "nuclei_pass1.jsonl").write_text(stale + "\n", encoding="utf-8")
    scheduler, ctx, _ = run_dag(tmp_path, monkeypatch, nuclei=True, nuclei_passes="2")
    assert statuses(scheduler)["nuclei1"] is Status.SKIPPED
    counts = finalize_nuclei(ctx)
    assert "stale" not in (tmp_path / "nuclei.txt").read_text(encoding="utf-8") and "critical" not in counts


def test_no_pass_ran_removes_a_stale_view(tmp_path, monkeypatch):
    (tmp_path / "nuclei.txt").write_text("[critical] stale https://old\n", encoding="utf-8")
    scheduler, ctx, tools = run_dag(tmp_path, monkeypatch, missing={"nuclei"}, nuclei=True)
    assert statuses(scheduler)["nuclei1"] is Status.DISABLED and statuses(scheduler)["nuclei2"] is Status.DISABLED
    assert "nuclei" not in tools.calls
    assert finalize_nuclei(ctx) is None and not (tmp_path / "nuclei.txt").exists()
