"""Benchmark SYNTHÉTIQUE du pipeline : séquentiel vs parallèle, avec et sans `-n`.

Ce n'est PAS une mesure : aucun outil réel n'est lancé et aucune requête n'est envoyée. On
exécute le vrai ordonnanceur (`Scheduler`) sur le vrai DAG de modules (`build_modules`), avec de
faux outils (`runner.run_command` remplacé, comme dans les tests) dont chaque module « dure » le
temps d'un run réaliste, mis à l'échelle (1 s simulée = 1 min réelle par défaut). Ce qui est
validé : l'ordre des dépendances, le budget de débit (--max-rps), le nombre de workers et le
chevauchement de nuclei #1 avec katana. Les durées réelles, elles, se mesurent sur une cible
autorisée avec `run_stats.json` (voir README, « Durées : séquentiel vs parallèle »).

Usage (depuis la racine du dépôt) ::

    python -m bench.bench_pipeline              # échelle 1 s = 1 min : ~6 min de calcul au total
    python -m bench.bench_pipeline --scale 0.25 # 4 fois plus vite (un peu moins précis)
    python bench/bench_pipeline.py --scale 0.1

Les chiffres sont toujours convertis en « minutes simulées » (secondes mesurées / échelle).
Code de sortie 1 si nuclei #1 ne chevauche pas katana en parallèle avec -n.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
import time
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:        # `python bench/bench_pipeline.py` : la racine n'est pas dans sys.path
    sys.path.insert(0, str(ROOT))

from recon_mano import runner, ui  # noqa: E402
from recon_mano.modules import Options, build_modules  # noqa: E402
from recon_mano.pipeline import DEFAULT_WORKERS, Context, Module, ModuleResult, Scheduler, build_paths  # noqa: E402
from recon_mano.scope import ScopeFilter  # noqa: E402
from tests.test_modules import FakeCrtsh, FakeTools  # noqa: E402  (faux outils des tests : sorties plausibles)

# Durée de chaque module, en minutes simulées (un run réaliste de taille moyenne). Les modules à
# 0 n'ont pas de durée propre (fusions, rendu local). nuclei2 couvre ses deux runs (DAST + exposition).
DURATIONS_MIN: Dict[str, float] = {
    "subfinder": 2, "crtsh": 1, "amass": 10, "subdomains": 0, "dnsx": 1,
    "urlfinder": 3, "gau": 4, "waybackurls": 3,
    "httpx": 3, "nuclei1": 20, "katana": 40,
    "takeover": 2, "naabu": 15, "httpx_ports": 2, "nuclei_ports": 5,
    "jsluice": 1, "secrets": 2, "merge_map": 0, "httpx2": 4, "tree": 0,
    "arjun": 10, "nuclei2": 15,
}


@dataclass
class Scenario:
    label: str
    sequential: bool
    nuclei: bool
    scale: float
    wall: float = 0.0                                   # secondes mesurées
    modules: List[Dict[str, Any]] = field(default_factory=list)   # name, status, start, end, rate (secondes mesurées)

    @property
    def wall_min(self) -> float:
        return self.wall / self.scale

    def record(self, name: str) -> Optional[Dict[str, Any]]:
        return next((m for m in self.modules if m["name"] == name), None)

    def overlaps(self, first: str, second: str) -> bool:
        a, b = self.record(first), self.record(second)
        if not a or not b or None in (a["start"], a["end"], b["start"], b["end"]):
            return False
        return a["start"] < b["end"] and b["start"] < a["end"] and a["status"] == b["status"] == "done"


def padded(run: Callable[..., ModuleResult], seconds: float) -> Callable[..., ModuleResult]:
    """Le module fait son vrai travail (faux outils, instantané) puis « dure » `seconds` au total."""
    def _run(ctx: Context) -> ModuleResult:
        started = time.monotonic()
        result = run(ctx)
        time.sleep(max(seconds - (time.monotonic() - started), 0.0))
        return result
    return _run


@contextmanager
def fake_environment() -> Iterator[None]:
    """Aucun outil réel, aucun réseau : run_command, which, resolve_httpx et crt.sh sont remplacés."""
    quiet = ui.console.quiet
    ui.console.quiet = True
    try:
        with mock.patch.object(runner, "run_command", FakeTools()), \
                mock.patch.object(runner, "resolve_httpx", lambda explicit=None: "httpx"), \
                mock.patch.object(urllib.request, "urlopen", FakeCrtsh()), \
                mock.patch.object(shutil, "which", lambda name, *a, **k: f"/fake/{name}"):
            yield
    finally:
        ui.console.quiet = quiet


def run_scenario(
    label: str, *, sequential: bool, nuclei: bool, scale: float = 1.0, max_rps: int = 150,
    workers: int = DEFAULT_WORKERS, durations: Optional[Dict[str, float]] = None,
    workdir: Optional[Path] = None,
) -> Scenario:
    """Un run complet du DAG : `sequential` = un module à la fois (ancien comportement), `nuclei` = `-n`."""
    durations = DURATIONS_MIN if durations is None else durations
    scenario = Scenario(label, sequential, nuclei, scale)
    with tempfile.TemporaryDirectory(prefix="recon_bench_") as temp, fake_environment():
        output = workdir or Path(temp)
        output.mkdir(parents=True, exist_ok=True)
        options = Options(target="example.com", urlfinder_retries=0, live_code_set={200, 301}, nuclei=nuclei, crtsh_backoff=0)
        paths = build_paths(output)
        ctx = Context("example.com", output, paths, options, ScopeFilter(["example.com"], [], paths["rejected_scope"]))
        ctx.state["httpx_path"] = "httpx"
        modules: List[Module] = build_modules(options)
        for module in modules:
            module.run = padded(module.run, durations.get(module.name, 0.0) * scale)
        scheduler = Scheduler(modules, ctx, max_workers=1 if sequential else workers, max_rps=max_rps, live=False, poll=0.02)
        scheduler.run()
        scenario.wall = scheduler.wall_clock
        scenario.modules = [
            {"name": r.name, "status": r.status.value, "start": r.start, "end": r.end, "rate": r.rate}
            for r in scheduler.records.values()
        ]
    return scenario


def run_all(scale: float = 1.0, names: Optional[List[str]] = None) -> List[Scenario]:
    """Les quatre scénarios : séquentiel / parallèle × sans / avec -n."""
    plan = [
        ("séquentiel", True, False), ("parallèle", False, False),
        ("séquentiel + -n", True, True), ("parallèle + -n", False, True),
    ]
    return [
        run_scenario(label, sequential=seq, nuclei=n, scale=scale)
        for label, seq, n in plan if names is None or label in names
    ]


def _minutes(seconds: Optional[float], scale: float) -> str:
    return "     –" if seconds is None else f"{seconds / scale:6.1f}"


def format_report(scenarios: List[Scenario]) -> str:
    """Tableau de comparaison + chronologie par module des runs parallèles, en minutes simulées."""
    out: List[str] = ["SIMULATION (faux outils, durées scénarisées) - minutes simulées", ""]
    out.append(f"{'scénario':<20}{'durée (min)':>12}{'gain vs séquentiel':>22}")
    by_label = {s.label: s for s in scenarios}
    for s in scenarios:
        gain = ""
        base = by_label.get("séquentiel + -n" if s.nuclei else "séquentiel")
        if not s.sequential and base is not None and s.wall > 0:
            gain = f"x{base.wall / s.wall:.2f}  (-{(base.wall - s.wall) / s.scale:.0f} min)"
        out.append(f"{s.label:<20}{s.wall_min:>12.1f}{gain:>22}")
    for s in scenarios:
        if s.sequential:
            continue
        out += ["", f"Chronologie - {s.label}", f"  {'module':<14}{'début':>7}{'fin':>8}{'débit':>8}  statut"]
        for m in sorted(s.modules, key=lambda m: (m["start"] is None, m["start"] or 0.0)):
            if m["status"] == "skipped":
                continue
            rate = f"{m['rate']}/s" if m["rate"] else ""
            out.append(f"  {m['name']:<14}{_minutes(m['start'], s.scale):>7}{_minutes(m['end'], s.scale):>8}{rate:>8}  {m['status']}")
        if s.nuclei:
            out.append(f"  nuclei #1 chevauche katana : {'OUI' if s.overlaps('nuclei1', 'katana') else 'NON'}")
    return "\n".join(out)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--scale", type=float, default=1.0, help="secondes réelles par minute simulée (défaut 1.0)")
    args = parser.parse_args(argv)
    if args.scale <= 0:
        parser.error("--scale doit être > 0")
    scenarios = run_all(args.scale)
    print(format_report(scenarios))
    with_n = next((s for s in scenarios if s.label == "parallèle + -n"), None)
    return 0 if with_n is None or with_n.overlaps("nuclei1", "katana") else 1


if __name__ == "__main__":
    raise SystemExit(main())
