"""Le DAG réel (recon_mano.modules) piloté par l'ordonnanceur, avec de faux outils."""

from __future__ import annotations

import json
import shutil
import threading
import time
import zlib
from pathlib import Path

from recon_mano import runner
from recon_mano.modules import Options, build_modules
from recon_mano.pipeline import Context, Scheduler, Status, build_paths
from recon_mano.scope import ScopeFilter

HOSTS = ["www.example.com", "api.example.com", "evil.net"]
ARCHIVE = ["https://www.example.com/old", "https://cdn.thirdparty.io/x.js"]


class FakeTools:
    """Remplace run_command : écrit des sorties plausibles, note les appels."""

    def __init__(self, all_404=False, hosts=HOSTS):
        self.calls: list = []
        self.spans: dict = {}
        self.all_404 = all_404
        self.hosts = hosts
        self.lock = threading.Lock()

    def __call__(self, command, label, watch=None, timeout=None, stdout_to=None, silent=True):
        tool = Path(command[0]).name
        start = time.monotonic()
        with self.lock:
            self.calls.append(tool)
        arg = lambda flag: command[command.index(flag) + 1]  # noqa: E731
        stderr = ""
        if tool == "subfinder":
            time.sleep(0.15)
            Path(arg("-o")).write_text("\n".join(self.hosts) + "\n", encoding="utf-8")
        elif tool == "dnsx":
            hosts = Path(arg("-l")).read_text(encoding="utf-8").split()
            Path(arg("-o")).write_text("\n".join(h for h in hosts if "api" not in h) + "\n", encoding="utf-8")
        elif tool == "urlfinder":
            time.sleep(0.15)
            Path(arg("-o")).write_text("\n".join(ARCHIVE) + "\n", encoding="utf-8")
            stderr = "[INF] Found 2 urls in 1s\n"
        elif tool == "httpx":
            rows = []
            for item in Path(arg("-l")).read_text(encoding="utf-8").split():
                url = item if item.startswith("http") else f"https://{item}"
                code = 404 if self.all_404 else (200 if zlib.crc32(url.encode()) % 2 else 301)
                rows.append({"url": url, "status_code": code})
            Path(arg("-o")).write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        elif tool == "katana":
            seeds = Path(arg("-list")).read_text(encoding="utf-8").split()
            found = [s.rstrip("/") + "/admin" for s in seeds] + ["https://thirdparty.io/y"]
            Path(arg("-o")).write_text("\n".join(found) + "\n", encoding="utf-8")
        elif tool == "nuclei":
            targets = Path(arg("-l")).read_text(encoding="utf-8").split()
            Path(arg("-o")).write_text("".join(f"[info] {t}\n" for t in targets), encoding="utf-8")
        with self.lock:
            self.spans[tool] = (start, time.monotonic())
        return 0, 0.1, stderr


def run_dag(tmp_path, monkeypatch, tools=None, missing=(), **opts):
    tools = tools or FakeTools()
    monkeypatch.setattr(runner, "run_command", tools)
    monkeypatch.setattr(runner, "resolve_httpx", lambda explicit=None: "httpx")
    monkeypatch.setattr(
        shutil, "which", lambda name, *a, **k: None if name in missing else f"/fake/{name}"
    )
    options = Options(target="example.com", urlfinder_retries=0, live_code_set={200, 301}, **opts)
    paths = build_paths(tmp_path)
    ctx = Context(
        target="example.com", output=tmp_path, paths=paths, options=options,
        scope=ScopeFilter(["example.com"], [], paths["rejected_scope"]),
    )
    ctx.state["httpx_path"] = None if "httpx" in missing else "httpx"
    scheduler = Scheduler(build_modules(options), ctx, max_workers=4, live=False, poll=0.01)
    scheduler.run()
    return scheduler, ctx, tools


def statuses(scheduler):
    return {name: rec.status for name, rec in scheduler.records.items()}


def lines(path):
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


def test_full_run(tmp_path, monkeypatch):
    scheduler, ctx, tools = run_dag(tmp_path, monkeypatch, nuclei=True)
    assert all(s is Status.DONE for s in statuses(scheduler).values()), statuses(scheduler)
    assert lines(tmp_path / "01_subfinder.txt") == ["www.example.com", "api.example.com"]  # evil.net écarté
    assert lines(tmp_path / "02_dnsx.txt") == ["www.example.com"]
    assert lines(tmp_path / "03_urlfinder.txt") == ["https://www.example.com/old"]
    assert (tmp_path / "all_urls.txt").exists() and (tmp_path / "urls_tree.html").exists()
    assert (tmp_path / "run_stats.json").exists()
    assert "thirdparty.io" not in (tmp_path / "all_urls.txt").read_text(encoding="utf-8")
    assert scheduler.records["nuclei"].rate == 150 and scheduler.records["httpx"].rate == 150


def test_urlfinder_runs_in_parallel_with_subfinder(tmp_path, monkeypatch):
    scheduler, _, tools = run_dag(tmp_path, monkeypatch)
    sub, url = scheduler.records["subfinder"], scheduler.records["urlfinder"]
    assert url.start < sub.end and sub.start < url.end
    # httpx attend dnsx ET urlfinder.
    httpx = scheduler.records["httpx"]
    assert httpx.start >= scheduler.records["dnsx"].end and httpx.start >= url.end


def test_zero_live_urls_skips_katana_and_everything_downstream(tmp_path, monkeypatch):
    tools = FakeTools(all_404=True)
    scheduler, ctx, _ = run_dag(tmp_path, monkeypatch, tools=tools, nuclei=True)
    st = statuses(scheduler)
    assert st["httpx"] is Status.DONE
    assert st["katana"] is Status.SKIPPED
    assert "aucune URL vivante" in scheduler.records["katana"].note
    assert "katana" not in tools.calls                       # jamais lancé sur des cibles non confirmées
    assert st["httpx2"] is Status.SKIPPED and st["nuclei"] is Status.SKIPPED
    assert lines(tmp_path / "all_urls.txt") == []


def test_skip_httpx_keeps_legacy_raw_fallback_for_katana(tmp_path, monkeypatch):
    scheduler, ctx, tools = run_dag(tmp_path, monkeypatch, skip_httpx=True)
    st = statuses(scheduler)
    assert st["httpx"] is Status.SKIPPED and st["httpx2"] is Status.SKIPPED
    assert st["katana"] is Status.DONE
    assert "katana" in tools.calls and "httpx" not in tools.calls
    # katana est parti des entrées brutes fusionnées (hôtes dnsx + archives).
    assert "www.example.com/admin" in lines(tmp_path / "06_katana.txt")   # hôte nu, pas encore sondé
    assert scheduler.records["katana"].start >= scheduler.records["urlfinder"].end


def test_no_hosts_in_scope_fails_subfinder_and_downstream_skips(tmp_path, monkeypatch):
    tools = FakeTools(hosts=["evil.net", "other.org"])
    scheduler, ctx, _ = run_dag(tmp_path, monkeypatch, tools=tools, nuclei=True)
    st = statuses(scheduler)
    assert st["subfinder"] is Status.FAILED
    assert scheduler.records["subfinder"].note == "Aucun sous-domaine dans le périmètre, arrêt."
    assert st["urlfinder"] is Status.DONE                      # indépendant des hôtes
    for name in ("dnsx", "httpx", "katana", "merge_map", "httpx2", "tree", "nuclei"):
        assert st[name] is Status.SKIPPED, name
    assert tools.calls.count("httpx") == 0 and "katana" not in tools.calls
    assert scheduler.failed


def test_missing_dnsx_binary_falls_back_to_subfinder_hosts(tmp_path, monkeypatch):
    scheduler, ctx, tools = run_dag(tmp_path, monkeypatch, missing={"dnsx"})
    assert scheduler.records["dnsx"].status is Status.DISABLED
    assert "dnsx" not in tools.calls
    assert "api.example.com" in lines(tmp_path / "04_httpx_input.txt")   # liste subfinder, pas dnsx
    assert scheduler.records["httpx"].status is Status.DONE


def test_missing_httpx_disables_httpx_modules_and_katana_does_not_crawl(tmp_path, monkeypatch):
    scheduler, ctx, tools = run_dag(tmp_path, monkeypatch, missing={"httpx"})
    st = statuses(scheduler)
    assert st["httpx"] is Status.DISABLED and st["katana"] is Status.SKIPPED
    assert "katana" not in tools.calls


def test_nuclei_is_opt_in(tmp_path, monkeypatch):
    scheduler, ctx, tools = run_dag(tmp_path, monkeypatch)
    assert scheduler.records["nuclei"].status is Status.SKIPPED
    assert "nuclei" not in tools.calls and not (tmp_path / "nuclei.txt").exists()


def test_nuclei_targets_hosts_vs_urls(tmp_path, monkeypatch):
    (tmp_path / "h").mkdir()
    (tmp_path / "u").mkdir()
    run_dag(tmp_path / "h", monkeypatch, nuclei=True, nuclei_targets="hosts")
    run_dag(tmp_path / "u", monkeypatch, nuclei=True, nuclei_targets="urls")
    hosts = lines(tmp_path / "h" / "07_nuclei_input.txt")
    urls = lines(tmp_path / "u" / "07_nuclei_input.txt")
    assert all(h.count("/") == 2 for h in hosts)      # racines scheme://host
    assert len(urls) >= len(hosts)


def test_sequential_equals_parallel_outputs(tmp_path, monkeypatch):
    (tmp_path / "p").mkdir()
    (tmp_path / "s").mkdir()
    run_dag(tmp_path / "p", monkeypatch, nuclei=True)
    # même DAG avec un seul worker
    monkeypatch.setattr(runner, "run_command", FakeTools())
    options = Options(target="example.com", urlfinder_retries=0, live_code_set={200, 301}, nuclei=True)
    paths = build_paths(tmp_path / "s")
    ctx = Context("example.com", tmp_path / "s", paths, options, ScopeFilter(["example.com"], [], paths["rejected_scope"]))
    ctx.state["httpx_path"] = "httpx"
    Scheduler(build_modules(options), ctx, max_workers=1, live=False, poll=0.01).run()
    for name in ("01_subfinder.txt", "02_dnsx.txt", "03_urlfinder.txt", "04_httpx_input.txt", "05_httpx.jsonl",
                 "06_katana.txt", "all_urls.txt", "08_httpx2.jsonl", "urls_all_final.txt",
                 "urls_200_final.txt", "urls_live_final.txt", "07_nuclei_input.txt", "nuclei.txt", "urls_tree.html"):
        assert (tmp_path / "p" / name).read_bytes() == (tmp_path / "s" / name).read_bytes(), name
    assert sorted(lines(tmp_path / "p" / "rejected_scope.tsv")) == sorted(lines(tmp_path / "s" / "rejected_scope.tsv"))
