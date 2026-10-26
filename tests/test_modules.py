"""Le DAG réel (recon_mano.modules) piloté par l'ordonnanceur, avec de faux outils."""

from __future__ import annotations

import json
import shutil
import threading
import time
import urllib.error
import urllib.request
import zlib
from pathlib import Path

from urllib.parse import urlparse

from recon_mano import runner
from recon_mano.modules import Options, build_modules, finalize_nuclei
from recon_mano.pipeline import Context, Scheduler, Status, build_paths
from recon_mano.scope import ScopeFilter

HOSTS = ["www.example.com", "api.example.com", "evil.net"]
ARCHIVE = ["https://www.example.com/old", "https://cdn.thirdparty.io/x.js"]


def fake_status(url):
    """Code HTTP déterministe du faux httpx (même URL → même code, quelle que soit la passe)."""
    return 200 if zlib.crc32(url.encode()) % 2 else 301


class FakeResponse:
    """Réponse minimale d'`urllib.request.urlopen` (gestionnaire de contexte + read)."""

    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self.body


class FakeCrtsh:
    """Remplace `urllib.request.urlopen` : aucun accès réseau, jamais.

    `script` : liste d'étapes jouées dans l'ordre des appels — un `bytes`/`list` (corps JSON
    renvoyé), ou une exception (levée). Une fois épuisée, la dernière étape est rejouée.
    Par défaut : un certificat par appel avec `names`.
    """

    def __init__(self, names=("www.example.com",), script=None):
        self.requests: list = []
        self.script = list(script) if script is not None else [[{"name_value": chr(10).join(names)}]]
        self.lock = threading.Lock()

    def __call__(self, request, timeout=None):
        with self.lock:
            self.requests.append((request.full_url, timeout))
            step = self.script[min(len(self.requests) - 1, len(self.script) - 1)]
        if isinstance(step, BaseException):
            raise step
        body = step if isinstance(step, bytes) else json.dumps(step).encode("utf-8")
        return FakeResponse(body)


class FakeTools:
    """Remplace run_command : écrit des sorties plausibles, note les appels.

    - `commands` : [(label, commande complète)] dans l'ordre des appels ;
    - `spans` : label -> (début, fin) monotone ;
    - `waf_hosts` : hôtes que httpx annoncera derrière un WAF (si `-cdn` est passé) ;
    - `delays` : outil -> secondes de sommeil (pour chevaucher katana et nuclei) ;
    - `gf_hits` : motif gf -> URLs rendues (parmi celles reçues sur stdin) ;
    - `amass_names`, `gau_urls`, `wayback_urls` : ce que rendent amass (`subs`), gau et waybackurls.
    """

    def __init__(self, all_404=False, hosts=HOSTS, archive=ARCHIVE, waf_hosts=(), delays=None,
                 gf_hits=None, truncate_nuclei=False, amass_names=(), gau_urls=(), wayback_urls=(),
                 amass_rc=0, codes=None, unreachable=()):
        self.calls: list = []
        self.commands: list = []
        self.spans: dict = {}
        self.all_404 = all_404
        self.hosts = hosts
        self.archive = archive
        self.waf_hosts = set(waf_hosts)
        self.delays = delays or {}
        self.gf_hits = gf_hits or {}
        self.truncate_nuclei = truncate_nuclei
        self.amass_names = list(amass_names)
        self.gau_urls = list(gau_urls)
        self.wayback_urls = list(wayback_urls)
        self.amass_rc = amass_rc
        self.codes = codes or {}               # URL -> code imposé
        self.unreachable = set(unreachable)    # URLs que httpx n'écrit pas (timeout / refus de connexion)
        self.wayback_stdin = ""
        self.silent: dict = {}                 # label -> valeur du paramètre `silent` reçu
        self.lock = threading.Lock()

    def of(self, label):
        """Commandes lancées sous cette étiquette (ex. « nuclei #1 »)."""
        return [command for name, command in self.commands if name == label]

    def __call__(self, command, label, watch=None, timeout=None, stdout_to=None, silent=True, stdin_from=None):
        tool = Path(command[0]).name
        start = time.monotonic()
        with self.lock:
            self.calls.append(tool)
            self.commands.append((label, list(command)))
            self.silent[label] = silent
        arg = lambda flag: command[command.index(flag) + 1]  # noqa: E731
        stderr = ""
        time.sleep(self.delays.get(tool, 0))
        if tool == "subfinder":
            time.sleep(0.15)
            Path(arg("-o")).write_text("\n".join(self.hosts) + "\n", encoding="utf-8")
        elif tool == "dnsx":
            hosts = Path(arg("-l")).read_text(encoding="utf-8").split()
            Path(arg("-o")).write_text("\n".join(h for h in hosts if "api" not in h) + "\n", encoding="utf-8")
        elif tool == "amass":
            if "subs" in command:
                stdout_to.write_text("".join(n + chr(10) for n in self.amass_names), encoding="utf-8")
            elif self.amass_rc:
                with self.lock:
                    self.spans[label] = (start, time.monotonic())
                return self.amass_rc, 0.1, ""
        elif tool == "gau":
            stdout_to.write_text("".join(u + chr(10) for u in self.gau_urls), encoding="utf-8")
        elif tool == "waybackurls":
            self.wayback_stdin = stdin_from.read_text(encoding="utf-8")
            stdout_to.write_text("".join(u + chr(10) for u in self.wayback_urls), encoding="utf-8")
        elif tool == "urlfinder":
            time.sleep(0.15)
            Path(arg("-o")).write_text("\n".join(self.archive) + "\n", encoding="utf-8")
            stderr = "[INF] Found 2 urls in 1s\n"
        elif tool == "httpx":
            rows = []
            for item in Path(arg("-l")).read_text(encoding="utf-8").split():
                url = item if item.startswith("http") else f"https://{item}"
                if url in self.unreachable:
                    continue
                code = self.codes.get(url) or (404 if self.all_404 else fake_status(url))
                row = {"url": url, "status_code": code}
                if "-cdn" in command:
                    waf = urlparse(url).netloc in self.waf_hosts
                    row.update(cdn=waf, cdn_name="cloudflare" if waf else "", cdn_type="waf" if waf else "")
                rows.append(row)
            Path(arg("-o")).write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        elif tool == "katana":
            seeds = Path(arg("-list")).read_text(encoding="utf-8").split()
            found = [s.rstrip("/") + "/admin" for s in seeds] + ["https://thirdparty.io/y"]
            Path(arg("-o")).write_text("\n".join(found) + "\n", encoding="utf-8")
        elif tool == "nuclei":
            targets = Path(arg("-l")).read_text(encoding="utf-8").split()
            severity = "high" if "-dast" in command else ("medium" if "-as" in command else "info")
            out = [
                json.dumps({"template-id": f"fake-{severity}", "info": {"severity": severity}, "matched-at": t})
                for t in targets
            ]
            if self.truncate_nuclei:
                out.append('{"template-id": "coupé en plein')  # outil tué en pleine écriture
            Path(arg("-o")).write_text("".join(line + "\n" for line in out), encoding="utf-8")
        elif tool == "gf":
            if "-list" in command:
                stdout_to.write_text("\n".join(self.gf_hits) + "\n", encoding="utf-8")
            else:
                received = stdin_from.read_text(encoding="utf-8").split()
                stdout_to.write_text(
                    "".join(u + "\n" for u in self.gf_hits.get(command[1], []) if u in received), encoding="utf-8"
                )
        with self.lock:
            self.spans[label] = (start, time.monotonic())
        return 0, 0.1, stderr


def make_ctx(tmp_path, missing=(), scope=("example.com",), **opts):
    """Contexte prêt à l'emploi (outils factices et which patchés par l'appelant)."""
    opts.setdefault("crtsh_backoff", 0)   # jamais d'attente réelle entre deux essais crt.sh
    options = Options(target="example.com", urlfinder_retries=0, live_code_set={200, 301}, **opts)
    paths = build_paths(tmp_path)
    ctx = Context(
        target="example.com", output=tmp_path, paths=paths, options=options,
        scope=ScopeFilter(list(scope), [], paths["rejected_scope"]),
    )
    ctx.state["httpx_path"] = None if "httpx" in missing else "httpx"
    return ctx


def run_dag(tmp_path, monkeypatch, tools=None, missing=(), max_rps=150, crtsh_fake=None, **opts):
    tools = tools or FakeTools()
    monkeypatch.setattr(runner, "run_command", tools)
    monkeypatch.setattr(urllib.request, "urlopen", crtsh_fake or FakeCrtsh())
    monkeypatch.setattr(runner, "resolve_httpx", lambda explicit=None: "httpx")
    monkeypatch.setattr(
        shutil, "which", lambda name, *a, **k: None if name in missing else f"/fake/{name}"
    )
    ctx = make_ctx(tmp_path, missing, **opts)
    scheduler = Scheduler(build_modules(ctx.options), ctx, max_workers=4, max_rps=max_rps, live=False, poll=0.01)
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
    # nuclei #1 (50) se partage le budget avec katana ; nuclei #2 (150) tourne en fin de pipeline.
    assert scheduler.records["nuclei1"].rate == 50 and scheduler.records["nuclei2"].rate == 150
    assert scheduler.records["httpx"].rate == 150


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
    assert st["httpx2"] is Status.SKIPPED
    assert st["nuclei1"] is Status.SKIPPED and st["nuclei2"] is Status.SKIPPED
    assert "nuclei" not in tools.calls
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


def test_no_hosts_in_scope_fails_subdomains_and_downstream_skips(tmp_path, monkeypatch):
    tools = FakeTools(hosts=["evil.net", "other.org"])
    scheduler, ctx, _ = run_dag(tmp_path, monkeypatch, tools=tools, crtsh_fake=FakeCrtsh(script=[[]]), nuclei=True)
    st = statuses(scheduler)
    # Les sources vides ne sont plus fatales une à une : c'est la fusion qui arrête le pipeline.
    assert st["subfinder"] is Status.DONE and st["crtsh"] is Status.DONE and st["amass"] is Status.DONE
    assert scheduler.records["subfinder"].note == "aucun sous-domaine dans le périmètre"
    assert st["subdomains"] is Status.FAILED
    assert scheduler.records["subdomains"].note == "Aucun sous-domaine dans le périmètre, arrêt."
    assert st["urlfinder"] is Status.DONE                      # indépendant des hôtes
    for name in ("dnsx", "httpx", "katana", "merge_map", "httpx2", "tree", "nuclei1", "nuclei2"):
        assert st[name] is Status.SKIPPED, name
    assert tools.calls.count("httpx") == 0 and "katana" not in tools.calls
    assert scheduler.failed


def test_nothing_found_anywhere_fails_with_the_historic_message(tmp_path, monkeypatch):
    tools = FakeTools(hosts=[])
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, tools=tools, crtsh_fake=FakeCrtsh(script=[[]]))
    assert scheduler.records["subdomains"].note == "Aucun sous-domaine trouvé, arrêt."
    assert statuses(scheduler)["dnsx"] is Status.SKIPPED


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
    for name in ("nuclei1", "nuclei2"):
        assert scheduler.records[name].status is Status.SKIPPED
        assert "option" in scheduler.records[name].note
    assert "nuclei" not in tools.calls and finalize_nuclei(ctx) is None
    assert not (tmp_path / "nuclei.txt").exists()
    # Sans -n : katana a tout le budget, httpx garde sa commande d'avant (pas de -cdn).
    assert scheduler.records["katana"].rate == 150
    assert all("-cdn" not in command for _, command in tools.commands)


def test_sequential_equals_parallel_outputs(tmp_path, monkeypatch):
    (tmp_path / "p").mkdir()
    (tmp_path / "s").mkdir()
    def rich_tools():
        return FakeTools(
            amass_names=["amass.example.com"], gau_urls=["https://www.example.com/g1", "https://www.example.com/g2?a=1"],
            wayback_urls=["https://www.example.com/w1"],
        )

    _, parallel_ctx, _ = run_dag(tmp_path / "p", monkeypatch, tools=rich_tools(), nuclei=True)
    finalize_nuclei(parallel_ctx)
    # même DAG avec un seul worker
    monkeypatch.setattr(runner, "run_command", rich_tools())
    options = Options(target="example.com", urlfinder_retries=0, live_code_set={200, 301}, nuclei=True)
    paths = build_paths(tmp_path / "s")
    ctx = Context("example.com", tmp_path / "s", paths, options, ScopeFilter(["example.com"], [], paths["rejected_scope"]))
    ctx.state["httpx_path"] = "httpx"
    Scheduler(build_modules(options), ctx, max_workers=1, live=False, poll=0.01).run()
    finalize_nuclei(ctx)
    for name in ("01_subfinder.txt", "01b_crtsh.txt", "01c_amass.txt", "01_subdomains.txt", "02_dnsx.txt",
                 "03_urlfinder.txt", "03b_gau.txt", "03c_waybackurls.txt", "04_httpx_input.txt", "05_httpx.jsonl",
                 "06_katana.txt", "all_urls.txt", "08_httpx2_input.txt", "08_httpx2.jsonl", "urls_all_final.txt",
                 "urls_200_final.txt", "urls_live_final.txt", "07_nuclei1_input.txt", "07_nuclei2_input.txt",
                 "07_nuclei2_priority.txt", "nuclei_pass1.jsonl", "nuclei_pass2.jsonl", "nuclei.txt",
                 "urls_tree.html"):
        assert (tmp_path / "p" / name).read_bytes() == (tmp_path / "s" / name).read_bytes(), name
    assert sorted(lines(tmp_path / "p" / "rejected_scope.tsv")) == sorted(lines(tmp_path / "s" / "rejected_scope.tsv"))
