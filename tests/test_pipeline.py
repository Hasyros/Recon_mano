"""Tests de l'ordonnanceur (recon_mano.pipeline) avec de faux modules — aucun subprocess."""

from __future__ import annotations

import json
import shutil
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from recon_mano import runner, ui
from recon_mano.pipeline import (
    Context,
    Module,
    ModuleError,
    ModuleResult,
    ModuleSkipped,
    RateBudget,
    Scheduler,
    Status,
    build_paths,
    validate_modules,
)
from recon_mano.scope import ScopeFilter


def make_ctx(tmp_path):
    return Context(
        target="example.com",
        output=tmp_path,
        paths=build_paths(tmp_path),
        options=SimpleNamespace(httpx_bin=None),
        scope=ScopeFilter(["example.com"], enabled=False),
    )


def run(tmp_path, modules, **kwargs):
    ctx = make_ctx(tmp_path)
    kwargs.setdefault("live", False)
    kwargs.setdefault("poll", 0.01)
    scheduler = Scheduler(modules, ctx, **kwargs)
    scheduler.run()
    return scheduler


def ok(count=1):
    return lambda ctx: ModuleResult(count)


def sleeper(seconds, journal=None, count=1):
    """Module factice : dort, et note ses instants de début/fin dans `journal`."""
    def _run(ctx):
        if journal is not None:
            journal.append(("start", ctx.module, time.monotonic()))
        time.sleep(seconds)
        if journal is not None:
            journal.append(("end", ctx.module, time.monotonic()))
        return ModuleResult(count)
    return _run


def status_of(scheduler, name):
    return scheduler.records[name].status


# --------------------------------------------------------------------------- #
# Dépendances
# --------------------------------------------------------------------------- #


def test_dependency_order_respected(tmp_path):
    journal: list = []
    modules = [
        Module("c", ["b"], sleeper(0.05, journal)),
        Module("b", ["a"], sleeper(0.05, journal)),
        Module("a", [], sleeper(0.05, journal)),
    ]
    run(tmp_path, modules, max_workers=4)
    events = [(kind, name) for kind, name, _ in journal]
    assert events == [("start", "a"), ("end", "a"), ("start", "b"), ("end", "b"), ("start", "c"), ("end", "c")]


def test_independent_modules_overlap(tmp_path):
    modules = [Module("a", [], sleeper(0.3)), Module("b", [], sleeper(0.3))]
    started = time.monotonic()
    scheduler = run(tmp_path, modules, max_workers=2)
    assert time.monotonic() - started < 0.5
    a, b = scheduler.records["a"], scheduler.records["b"]
    assert a.start < b.end and b.start < a.end  # les deux fenêtres se chevauchent


def test_single_worker_runs_one_at_a_time(tmp_path):
    journal: list = []
    modules = [Module("a", [], sleeper(0.1, journal)), Module("b", [], sleeper(0.1, journal))]
    run(tmp_path, modules, max_workers=1)
    assert [(k, n) for k, n, _ in journal] == [("start", "a"), ("end", "a"), ("start", "b"), ("end", "b")]


def test_join_waits_for_all_deps(tmp_path):
    journal: list = []
    modules = [
        Module("fast", [], sleeper(0.05, journal)),
        Module("slow", [], sleeper(0.25, journal)),
        Module("join", ["fast", "slow"], sleeper(0.01, journal)),
    ]
    run(tmp_path, modules, max_workers=4)
    t = {(k, n): ts for k, n, ts in journal}
    assert t[("start", "join")] >= t[("end", "slow")]


def test_validate_modules_rejects_bad_graphs():
    with pytest.raises(ValueError, match="inconnue"):
        validate_modules([Module("a", ["ghost"], ok())])
    with pytest.raises(ValueError, match="cycle"):
        validate_modules([Module("a", ["b"], ok()), Module("b", ["a"], ok())])
    with pytest.raises(ValueError, match="double"):
        validate_modules([Module("a", [], ok()), Module("a", [], ok())])


# --------------------------------------------------------------------------- #
# Échecs, ignorés, désactivés
# --------------------------------------------------------------------------- #


def test_raising_module_fails_but_pipeline_continues(tmp_path):
    ran: list = []

    def boom(ctx):
        raise RuntimeError("kaboom")

    def after(ctx):
        # Les dépendants d'un module en échec tournent quand même (à eux de s'adapter).
        ran.append(ctx.status("boom"))
        return ModuleResult(2)

    modules = [
        Module("boom", [], boom),
        Module("after", ["boom"], after),
        Module("other", [], sleeper(0.05)),
    ]
    scheduler = run(tmp_path, modules, max_workers=4)
    assert status_of(scheduler, "boom") is Status.FAILED
    assert "kaboom" in scheduler.records["boom"].note
    assert status_of(scheduler, "after") is Status.DONE and ran == [Status.FAILED]
    assert status_of(scheduler, "other") is Status.DONE
    assert scheduler.failed


def test_module_error_is_failed_without_traceback(tmp_path, capsys):
    def nope(ctx):
        raise ModuleError("Aucun sous-domaine trouvé, arrêt.")

    scheduler = run(tmp_path, [Module("nope", [], nope)])
    assert status_of(scheduler, "nope") is Status.FAILED
    out = capsys.readouterr().out
    assert "Aucun sous-domaine trouvé" in out
    assert "Traceback" not in out


def test_module_skipped_exception(tmp_path):
    def nothing(ctx):
        raise ModuleSkipped("rien à faire")

    scheduler = run(tmp_path, [Module("nothing", [], nothing), Module("next", ["nothing"], ok())])
    assert status_of(scheduler, "nothing") is Status.SKIPPED
    assert scheduler.records["nothing"].note == "rien à faire"
    assert status_of(scheduler, "next") is Status.DONE
    assert not scheduler.failed


def test_missing_binary_disables_module(tmp_path, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: "/bin/present" if name == "present" else None)
    called: list = []

    def must_not_run(ctx):
        called.append(ctx.module)
        return ModuleResult(1)

    modules = [
        Module("ghost", [], must_not_run, binaries=["absent-tool"]),
        Module("real", [], ok(5), binaries=["present"]),
        Module("dep", ["ghost"], ok(3)),
    ]
    scheduler = run(tmp_path, modules)
    ghost = scheduler.records["ghost"]
    assert ghost.status is Status.DISABLED
    assert ghost.note == "binaire absent-tool introuvable — module désactivé"
    assert called == []
    assert status_of(scheduler, "real") is Status.DONE
    assert status_of(scheduler, "dep") is Status.DONE  # le pipeline continue


def test_httpx_binary_uses_resolve_httpx(tmp_path, monkeypatch):
    # `httpx` du PATH = peut-être le client Python : on passe par resolve_httpx, pas which.
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: "/bin/httpx")
    monkeypatch.setattr(runner, "resolve_httpx", lambda explicit=None: None)
    scheduler = run(tmp_path, [Module("httpx", [], ok(), binaries=["httpx"])])
    assert status_of(scheduler, "httpx") is Status.DISABLED

    monkeypatch.setattr(runner, "resolve_httpx", lambda explicit=None: "/go/bin/httpx")
    scheduler = run(tmp_path, [Module("httpx", [], ok(), binaries=["httpx"])])
    assert status_of(scheduler, "httpx") is Status.DONE


def test_disabled_by_flag_is_skipped_after_its_deps(tmp_path):
    journal: list = []
    modules = [
        Module("first", [], sleeper(0.15, journal)),
        Module("off", ["first"], ok(), enabled=False),
        Module("after_off", ["off"], sleeper(0.01, journal)),
    ]
    scheduler = run(tmp_path, modules, max_workers=4)
    assert status_of(scheduler, "off") is Status.SKIPPED
    assert "option" in scheduler.records["off"].note
    t = {(k, n): ts for k, n, ts in journal}
    # `off` n'est résolu qu'une fois `first` terminé : l'ordre historique est préservé.
    assert t[("start", "after_off")] >= t[("end", "first")]


# --------------------------------------------------------------------------- #
# Timeout
# --------------------------------------------------------------------------- #


def test_module_returning_after_deadline_is_timeout(tmp_path):
    seen: dict = {}

    def slow(ctx):
        seen["remaining"] = ctx.remaining()
        time.sleep(0.4)
        return ModuleResult(7)

    scheduler = run(tmp_path, [Module("slow", [], slow, timeout=0.2), Module("next", ["slow"], ok())])
    rec = scheduler.records["slow"]
    assert rec.status is Status.TIMEOUT
    assert rec.count == 7  # le résultat partiel est conservé
    assert seen["remaining"] is not None and seen["remaining"] >= 1
    assert status_of(scheduler, "next") is Status.DONE


def test_no_timeout_means_no_deadline(tmp_path):
    seen: dict = {}

    def probe(ctx):
        seen["remaining"] = ctx.remaining()
        return ModuleResult(0)

    run(tmp_path, [Module("probe", [], probe)])
    assert seen["remaining"] is None


def test_run_command_timeout_kills_process(tmp_path):
    started = time.monotonic()
    rc, elapsed, _ = runner.run_command(
        [sys.executable, "-c", "import time; time.sleep(60)"], "sleeper", timeout=1, silent=False
    )
    assert rc == 124
    assert time.monotonic() - started < 15
    assert not runner._PROCS  # aucun processus orphelin enregistré


def test_run_command_publishes_progress_in_shared_registry(tmp_path):
    out = tmp_path / "out.txt"
    code = (
        "import time\n"
        f"f = open({str(out)!r}, 'w')\n"
        "for i in range(8):\n"
        "    f.write('l%d\\n' % i); f.flush(); time.sleep(0.15)\n"
    )
    ui.bind_module("probe")
    try:
        rc, _, _ = runner.run_command([sys.executable, "-c", code], "probe", watch=out, silent=False)
    finally:
        ui.bind_module(None)
    assert rc == 0
    assert ui.PROGRESS.get("probe") == 8  # compteur de lignes lu dans le fichier surveillé


def test_run_command_verbose_prefixes_stderr(capsys):
    runner.set_verbose(True)
    try:
        runner.run_command([sys.executable, "-c", "import sys; print('bonjour', file=sys.stderr)"], "mytool")
    finally:
        runner.set_verbose(False)
    assert "mytool │ bonjour" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# Budget de débit global
# --------------------------------------------------------------------------- #


def test_budget_grants_min_of_wanted_and_remaining():
    budget = RateBudget(150)
    assert budget.acquire(100) == 100
    assert budget.acquire(100) == 50      # le reste, pas plus
    assert budget.acquire(100) is None    # épuisé : attendre
    budget.release(100)
    assert budget.acquire(100) == 100
    assert budget.used == 150


def test_budget_floor_is_min_rate_and_ten():
    budget = RateBudget(100)
    assert budget.acquire(95) == 95
    assert budget.acquire(50) is None     # reste 5 < min(50, 10)
    assert budget.acquire(3) == 3         # reste 5 ≥ min(3, 10)
    assert budget.acquire(10) is None     # reste 2 < 10


def test_budget_never_blocks_forever_with_tiny_max_rps():
    budget = RateBudget(5)
    assert budget.acquire(150) == 5       # plancher borné par le budget total


def test_scheduler_never_exceeds_max_rps(tmp_path):
    lock = threading.Lock()
    state = {"sum": 0, "peak": 0, "granted": {}}

    def net(ctx):
        with lock:
            state["sum"] += ctx.rate
            state["peak"] = max(state["peak"], state["sum"])
            state["granted"][ctx.module] = ctx.rate
        time.sleep(0.15)
        with lock:
            state["sum"] -= ctx.rate
        return ModuleResult(1)

    modules = [Module(n, [], net, network=True, rate=100) for n in ("a", "b", "c")]
    scheduler = run(tmp_path, modules, max_workers=3, max_rps=150)
    assert state["peak"] <= 150
    assert state["granted"]["a"] == 100
    assert state["granted"]["b"] == 50            # reste du budget, pas la demande
    assert scheduler.records["b"].requested_rate == 100
    assert scheduler.records["b"].rate == 50
    # c n'a rien eu tant que a ou b tournaient : il démarre après la première libération.
    first_end = min(scheduler.records["a"].end, scheduler.records["b"].end)
    assert scheduler.records["c"].start >= first_end - 1e-3
    assert all(r.status is Status.DONE for r in scheduler.records.values())


def test_network_module_waits_when_budget_exhausted(tmp_path):
    journal: list = []

    def net(ctx):
        journal.append(("start", ctx.module, time.monotonic()))
        time.sleep(0.2)
        journal.append(("end", ctx.module, time.monotonic()))
        return ModuleResult(1)

    modules = [Module("a", [], net, network=True, rate=100), Module("b", [], net, network=True, rate=100)]
    scheduler = run(tmp_path, modules, max_workers=4, max_rps=100)
    t = {(k, n): ts for k, n, ts in journal}
    assert t[("start", "b")] >= t[("end", "a")]
    assert scheduler.records["b"].rate == 100      # reçoit tout le budget une fois libéré


def test_non_network_modules_take_no_budget(tmp_path):
    modules = [
        Module("net", [], sleeper(0.2), network=True, rate=100),
        Module("free", [], sleeper(0.2)),
    ]
    started = time.monotonic()
    scheduler = run(tmp_path, modules, max_workers=4, max_rps=100)
    assert time.monotonic() - started < 0.38  # en parallèle, malgré un budget saturé
    assert scheduler.records["free"].rate == 0


def test_interrupt_stops_cleanly_and_still_writes_stats(tmp_path):
    def stop(ctx):
        raise KeyboardInterrupt

    scheduler = Scheduler(
        [Module("a", [], stop), Module("b", ["a"], ok())], make_ctx(tmp_path), live=False, poll=0.01
    )
    with pytest.raises(KeyboardInterrupt):
        scheduler.run()
    assert status_of(scheduler, "a") is Status.FAILED
    assert status_of(scheduler, "b") is Status.SKIPPED
    assert "interrompu" in scheduler.records["b"].note
    assert (tmp_path / "run_stats.json").exists()


# --------------------------------------------------------------------------- #
# run_stats.json + journal
# --------------------------------------------------------------------------- #


def test_run_stats_json(tmp_path):
    modules = [
        Module("a", [], sleeper(0.2, count=4)),
        Module("b", [], sleeper(0.2, count=6)),
        Module("c", ["a", "b"], ok(1)),
        Module("off", [], ok(), enabled=False),
    ]
    scheduler = run(tmp_path, modules, max_workers=2)
    stats = json.loads((tmp_path / "run_stats.json").read_text(encoding="utf-8"))

    assert stats["workers"] == 2
    assert {m["name"] for m in stats["modules"]} == {"a", "b", "c", "off"}
    by_name = {m["name"]: m for m in stats["modules"]}
    assert by_name["a"]["status"] == "done" and by_name["a"]["count"] == 4
    assert by_name["off"]["status"] == "skipped"
    assert by_name["c"]["start"] >= max(by_name["a"]["end"], by_name["b"]["end"]) - 1e-3
    # En parallèle, la durée réelle est plus courte que le cumul des modules.
    assert stats["wall_clock"] <= stats["sum_of_durations"]
    assert stats["parallel_gain"] == pytest.approx(stats["sum_of_durations"] - stats["wall_clock"], abs=0.01)
    assert stats["parallel_gain"] > 0.1
    assert scheduler.wall_clock == pytest.approx(stats["wall_clock"], abs=0.01)


def test_summary_rows_in_start_order(tmp_path):
    modules = [Module("late", ["early"], ok()), Module("early", [], sleeper(0.05))]
    scheduler = run(tmp_path, modules)
    assert [r.name for r in scheduler.summary_rows()] == ["early", "late"]


def test_log_lines_are_flushed_with_module_result(tmp_path, capsys):
    def talk(ctx):
        ctx.log("  détail du module")
        return ModuleResult(3)

    run(tmp_path, [Module("talk", [], talk, desc="parle")])
    out = capsys.readouterr().out
    assert "talk" in out and "détail du module" in out and "3 entrées" in out
