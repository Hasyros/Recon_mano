"""Registre de modules (config.py), options de la CLI, --check, --clean, icônes."""

from __future__ import annotations

import json
import shutil
import urllib.request

import pytest
import typer
import typer.main
from rich.cells import cell_len
from typer.testing import CliRunner

from recon_mano import runner
from recon_mano.cli import ARTIFACT_NAMES, check_tools, clean_artifacts, main
from recon_mano.config import (
    MODULE_DEFAULTS,
    PRESETS,
    default_timeout_minutes,
    parse_module_timeouts,
    preset_modules,
)
from recon_mano.modules import Options, build_modules
from recon_mano.pipeline import ARTIFACTS
from recon_mano.ui import STAGE_ICONS

from .test_modules import FakeCrtsh, FakeTools


def app():
    application = typer.Typer()
    application.command()(main)
    return application


def params():
    return {p.name: p for p in typer.main.get_command(app()).params}


# --------------------------------------------------------------------------- #
# Registre
# --------------------------------------------------------------------------- #


def test_full_preset_lists_every_module_of_the_dag_in_order():
    built = [m.name for m in build_modules(Options(target="example.com"))]
    assert PRESETS["full"] == list(MODULE_DEFAULTS) == built
    assert preset_modules() == built
    with pytest.raises(ValueError, match="preset inconnu"):
        preset_modules("fast")                           # fast / surface : phase ultérieure
    assert set(PRESETS) == {"full"}


def test_defaults_in_the_registry_match_the_built_modules():
    for module in build_modules(Options(target="example.com")):
        default = MODULE_DEFAULTS[module.name]
        assert module.enabled == default.enabled, module.name
        assert module.timeout == default.timeout, module.name
        assert module.network == default.network and module.rate == default.rate, module.name
        assert tuple(module.binaries) == default.binaries, module.name


def test_nuclei_is_the_only_opt_in_module():
    assert [n for n, d in MODULE_DEFAULTS.items() if not d.enabled] == ["nuclei1", "nuclei2"]
    assert Options(target="x.com").nuclei is False
    assert all(m.enabled for m in build_modules(Options(target="x.com")) if not m.name.startswith("nuclei"))


def test_every_external_tool_has_a_timeout_default_and_network_ones_a_rate():
    for name, default in MODULE_DEFAULTS.items():
        if default.network:
            assert default.rate > 0, name                # débit configurable pour tout ce qui frappe la cible
    assert MODULE_DEFAULTS["amass"].timeout == 900 and MODULE_DEFAULTS["gau"].timeout == 900
    assert MODULE_DEFAULTS["waybackurls"].timeout == 900 and MODULE_DEFAULTS["crtsh"].params["request_timeout"] == 60
    assert not MODULE_DEFAULTS["crtsh"].network and not MODULE_DEFAULTS["gau"].network


def test_parse_module_timeouts():
    assert parse_module_timeouts(["amass=20", "gau=0", " Katana = 1.5 "]) == {"amass": 1200, "gau": None, "katana": 90}
    assert parse_module_timeouts([]) == {}
    for bad in ("amass", "amass=", "=5", "amass=x", "amass=-1", "inconnu=5"):
        with pytest.raises(ValueError):
            parse_module_timeouts([bad])
    assert default_timeout_minutes("amass") == 15 and default_timeout_minutes("katana") == 0


def test_module_timeout_override_beats_the_registry():
    options = Options(target="x.com", timeouts={"katana": 600, "amass": None})
    by_name = {m.name: m for m in build_modules(options)}
    assert by_name["katana"].timeout == 600 and by_name["amass"].timeout is None
    assert by_name["gau"].timeout == 900                  # défaut du registre conservé


# --------------------------------------------------------------------------- #
# Options de la CLI
# --------------------------------------------------------------------------- #


def test_cli_defaults_match_the_registry():
    p = params()
    assert p["all_sources"].default is True and "--no-all-sources" in p["all_sources"].secondary_opts
    for name in ("crtsh", "amass", "gau", "waybackurls", "archive_dedupe"):
        assert p[name].default is True, name
        assert f"--no-{name.replace('_', '-')}" in p[name].secondary_opts, name
    assert p["crtsh_timeout"].default == 60 and p["crtsh_retries"].default == 2
    assert p["amass_timeout"].default == 15 and p["gau_timeout"].default == 15 and p["waybackurls_timeout"].default == 15
    assert p["gau_threads"].default == 2 and p["archive_k"].default == 3
    assert p["rate_limit"].default == MODULE_DEFAULTS["httpx"].rate
    assert p["nuclei_rate_limit"].default == MODULE_DEFAULTS["nuclei1"].rate
    assert p["nuclei2_rate_limit"].default == MODULE_DEFAULTS["nuclei2"].rate
    assert p["nuclei"].default is False                    # seul module opt-in
    assert p["skip_subfinder"].default is False
    for name in ("crtsh", "amass", "gau", "waybackurls", "archive_dedupe", "archive_k", "amass_timeout", "gau_timeout",
                 "waybackurls_timeout", "crtsh_timeout", "module_timeout", "gau_threads"):
        assert p[name].help and len(p[name].help) > 20, name


def test_options_defaults_match_the_registry():
    o = Options(target="x.com")
    assert o.rate_limit == MODULE_DEFAULTS["httpx"].rate and o.threads == MODULE_DEFAULTS["httpx"].params["threads"]
    assert o.nuclei_rate_limit == MODULE_DEFAULTS["nuclei1"].rate and o.nuclei2_rate_limit == MODULE_DEFAULTS["nuclei2"].rate
    assert (o.crtsh_timeout, o.crtsh_retries) == (60, 2) and o.gau_threads == 2 and o.gau_http_timeout == 45
    assert o.archive_dedupe is True and o.archive_k == 3 and o.all_sources is True


@pytest.mark.parametrize("bad", [["--module-timeout", "amass"], ["--module-timeout", "ghost=3"], ["--module-timeout", "amass=x"],
                                  ["--archive-k", "0"], ["--crtsh-timeout", "0"], ["--amass-timeout", "-1"]])
def test_cli_rejects_bad_values(tmp_path, bad):
    result = CliRunner().invoke(app(), ["example.com", str(tmp_path / "out"), "-y", *bad])
    assert result.exit_code == 2, bad


def fake_environment(monkeypatch, tools=None, crtsh=None, missing=()):
    tools = tools or FakeTools()
    monkeypatch.setattr(runner, "run_command", tools)
    monkeypatch.setattr(runner, "resolve_httpx", lambda explicit=None: "httpx")
    monkeypatch.setattr(urllib.request, "urlopen", crtsh or FakeCrtsh())
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: None if name in missing else f"/fake/{name}")
    return tools


def test_cli_end_to_end_with_fakes(tmp_path, monkeypatch):
    tools = fake_environment(monkeypatch)
    out = tmp_path / "out"
    result = CliRunner().invoke(app(), ["example.com", str(out), "-y", "--module-timeout", "katana=30"])
    assert result.exit_code == 0, result.output
    config = json.loads((out / "run_config.json").read_text(encoding="utf-8"))
    for name in ("subfinder", "crtsh", "amass", "subdomains", "dnsx", "urlfinder", "gau", "waybackurls", "httpx",
                 "katana", "merge_map", "httpx2", "tree"):
        assert name in config["modules"], name
    assert "nuclei1" not in config["modules"] and "nuclei2" not in config["modules"]
    assert config["archive"] == {"dedupe": True, "k": 3}
    assert config["timeouts"]["amass"] == 900 and config["timeouts"]["katana"] == 1800
    assert "-all" in tools.of("subfinder")[0]
    for name in ("01_subdomains.txt", "01b_crtsh.txt", "01c_amass.txt", "03b_gau.txt", "03c_waybackurls.txt",
                 "08_httpx2_input.txt", "urls_200_final.txt"):
        assert (out / name).exists(), name
    stats = json.loads((out / "run_stats.json").read_text(encoding="utf-8"))
    assert {m["name"] for m in stats["modules"]} == set(MODULE_DEFAULTS)


def test_cli_flags_turn_modules_off(tmp_path, monkeypatch):
    fake = FakeCrtsh()
    tools = fake_environment(monkeypatch, crtsh=fake)
    out = tmp_path / "out"
    result = CliRunner().invoke(app(), [
        "example.com", str(out), "-y", "--no-crtsh", "--no-amass", "--no-gau", "--no-waybackurls",
        "--no-all-sources", "--no-archive-dedupe", "--archive-k", "5",
    ])
    assert result.exit_code == 0, result.output
    assert fake.requests == []
    assert not {"amass", "gau", "waybackurls"} & set(tools.calls)
    assert "-all" not in tools.of("subfinder")[0]
    config = json.loads((out / "run_config.json").read_text(encoding="utf-8"))
    assert not {"crtsh", "amass", "gau", "waybackurls"} & set(config["modules"])
    assert config["archive"] == {"dedupe": False, "k": 5}


def test_cli_nuclei_stays_opt_in_and_n_enables_both_passes(tmp_path, monkeypatch):
    tools = fake_environment(monkeypatch)
    CliRunner().invoke(app(), ["example.com", str(tmp_path / "a"), "-y"])
    assert "nuclei" not in tools.calls
    tools = fake_environment(monkeypatch)
    CliRunner().invoke(app(), ["example.com", str(tmp_path / "b"), "-y", "-n"])
    assert "nuclei" in tools.calls


# --------------------------------------------------------------------------- #
# --check, --clean, icônes
# --------------------------------------------------------------------------- #


def test_check_lists_the_new_optional_binaries_with_their_module(monkeypatch, capsys):
    monkeypatch.setattr(runner, "resolve_httpx", lambda explicit=None: "/fake/httpx")
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: None if name in ("amass", "waybackurls") else f"/fake/{name}")
    missing = check_tools()
    out = capsys.readouterr().out
    assert missing == []                                         # les nouveaux outils ne sont jamais « requis »
    assert "amass (optionnel, module amass) introuvable" in out
    assert "waybackurls (optionnel, module waybackurls) introuvable" in out
    assert "gau (optionnel, module gau) : /fake/gau" in out
    assert "nuclei (optionnel" in out and "gf (optionnel" in out
    assert "crtsh" in out and "aucun binaire" in out


def test_check_exit_code_ignores_optional_tools(monkeypatch):
    monkeypatch.setattr(runner, "resolve_httpx", lambda explicit=None: "/fake/httpx")
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: None if name in ("amass", "gau", "waybackurls", "nuclei", "gf") else f"/fake/{name}")
    result = CliRunner().invoke(app(), ["--check"])
    assert result.exit_code == 0 and "Tous les outils requis" in result.output


def test_new_artifacts_are_registered_and_cleaned(tmp_path):
    new = {
        "crtsh": "01b_crtsh.txt", "amass": "01c_amass.txt", "subdomains": "01_subdomains.txt",
        "gau": "03b_gau.txt", "waybackurls": "03c_waybackurls.txt", "httpx2_input": "08_httpx2_input.txt",
    }
    assert {k: ARTIFACTS[k] for k in new} == new
    names = list(new.values()) + [".waybackurls_domains.tmp"]
    for name in names:
        (tmp_path / name).write_text("x\n", encoding="utf-8")
    clean_artifacts(tmp_path)
    assert not [n for n in names if (tmp_path / n).exists()]
    assert set(ARTIFACTS.values()) <= set(ARTIFACT_NAMES)


def test_every_module_has_a_fixed_width_icon_without_variation_selector():
    for name in MODULE_DEFAULTS:
        icon = STAGE_ICONS.get(name)
        assert icon, f"pas d'icône pour {name}"
        assert "️" not in icon and cell_len(icon) == 2, name
    assert len({STAGE_ICONS[n] for n in ("crtsh", "amass", "subdomains", "gau", "waybackurls")}) == 5


def test_help_runs(tmp_path):
    result = CliRunner().invoke(app(), ["--help"])
    assert result.exit_code == 0
    for flag in ("--crtsh", "--amass", "--gau", "--waybackurls", "--archive-dedupe", "--module-timeout", "--no-all-sources"):
        assert flag in result.output, flag
