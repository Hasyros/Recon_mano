"""Phase 4b : helpers purs (recon_mano.surface) et constructeurs de commandes des nouveaux outils.

Aucun binaire, aucun accès réseau : les outils sont remplacés par `Recorder`.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from recon_mano import modules, runner, surface

from .test_sources import Recorder, flag

W = "https://www.example.com"


def store_response(directory: Path, url: str, status: str = "200 OK", content_type: str = "application/javascript",
                   body: str = "var a=1;", index: bool = True, spaces: bool = False) -> Path:
    """Écrit un fichier au format katana -store-response (URL, requête, réponse) et sa ligne d'index."""
    host = url.split("/")[2].replace(":", "_")
    folder = directory / (host + (" dir" if spaces else ""))
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / (hashlib.sha1(url.encode()).hexdigest() + ".txt")
    # write_bytes : write_text doublerait les « \r\n » sous Windows et casserait la séparation en-têtes / corps.
    target.write_bytes(
        f"{url}\n\n\nGET / HTTP/1.1\r\nHost: {host}\r\n\r\n\n\nHTTP/1.1 {status}\r\nContent-Type: {content_type}\r\n\r\n{body}".encode()
    )
    if index:
        with (directory / "index.txt").open("a", encoding="utf-8") as handle:
            handle.write(f"{target} {url} ({status})\n")
    return target


# --------------------------------------------------------------------------- #
# Réponses stockées par katana
# --------------------------------------------------------------------------- #


def test_katana_index_and_js_extraction(tmp_path):
    js = store_response(tmp_path, f"{W}/static/app.js", body="fetch('/api/x');")
    store_response(tmp_path, f"{W}/", content_type="text/html", body="<html></html>")
    store_response(tmp_path, f"{W}/missing.js", status="404 Not Found", body="nope")
    store_response(tmp_path, f"{W}/fake.js", content_type="text/html", body="<html>soft 404</html>")
    store_response(tmp_path, f"{W}/bundle", content_type="text/javascript; charset=utf-8", body="x=1")   # JS sans extension
    store_response(tmp_path, f"{W}/gone.js", index=False)                                                   # fichier orphelin
    (tmp_path / "index.txt").open("a", encoding="utf-8").write(f"{tmp_path}/ghost/none.txt {W}/ghost.js (200 OK)\n")   # fichier absent

    responses = surface.read_katana_index(tmp_path)
    assert [r.url for r in responses] == [f"{W}/static/app.js", f"{W}/", f"{W}/missing.js", f"{W}/fake.js", f"{W}/bundle"]
    assert responses[0].file == js and responses[0].status == "200 OK"

    out = tmp_path / "js"
    extracted, too_big = surface.extract_js_bodies(responses, out, 1000)
    assert sorted(url for _, url in extracted) == sorted([f"{W}/static/app.js", f"{W}/bundle"])   # ni HTML, ni 404, ni page
    body = next(path for path, url in extracted if url.endswith("app.js")).read_text(encoding="utf-8")
    assert body == "fetch('/api/x');"                       # corps seul : ni requête, ni en-têtes
    assert too_big == 0
    _, too_big = surface.extract_js_bodies(responses, tmp_path / "js2", 5)
    assert too_big == 1                                      # app.js (16 octets) dépasse la limite de 5 ; bundle (3) passe


def test_katana_index_handles_paths_with_spaces_and_relocated_dirs(tmp_path):
    store_response(tmp_path, f"{W}/a.js", spaces=True)
    (found,) = surface.read_katana_index(tmp_path)
    assert found.url == f"{W}/a.js" and " dir" in str(found.file)

    # Index écrit avec un chemin relatif au dossier de lancement de katana (« katana_response/hôte/… ») :
    relocated = tmp_path / "moved"
    relocated.mkdir()
    real = store_response(relocated, f"{W}/b.js")
    (relocated / "index.txt").write_text(f"katana_response/www.example.com/{real.name} {W}/b.js (200 OK)\n", encoding="utf-8")
    assert [r.file for r in surface.read_katana_index(relocated)] == [real]
    assert surface.read_katana_index(tmp_path / "absent") == []


def test_split_response_and_dir_size(tmp_path):
    headers, body = surface.split_response("http://x\n\n\nGET / HTTP/1.1\r\nHost: x\r\n\r\n\n\nHTTP/1.1 200 OK\r\nA: b\r\n\r\ncorps\n\nsuite")
    assert headers.startswith("HTTP/1.1 200 OK") and body == "corps\n\nsuite"
    assert surface.split_response("pas de réponse") == ("", "pas de réponse")
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "f.txt").write_text("12345", encoding="utf-8")
    assert surface.dir_size(tmp_path) == (1, 5) and surface.human_size(5) == "5 o" and surface.human_size(3 * 1024 * 1024) == "3.0 Mo"


# --------------------------------------------------------------------------- #
# jsluice
# --------------------------------------------------------------------------- #

BASE = f"{W}/static/js/app.js"


@pytest.mark.parametrize("raw, expected", [
    ("/api/users?id=EXPR&format=json", f"{W}/api/users?id=1&format=json"),     # relatif à la racine, EXPR de requête → 1
    ("v2/items", f"{W}/static/js/v2/items"),                                   # relatif au chemin du JS
    ("../up", f"{W}/static/up"),
    ("//cdn.thirdparty.io/x", "https://cdn.thirdparty.io/x"),                  # protocole relatif : schéma du JS
    ("https://api.example.com/graphql#frag", "https://api.example.com/graphql"),
    ("http://other.org:8080", "http://other.org:8080/"),
    ("EXPR/admin", None), ("/a/EXPR/b", None), ("https://EXPR.example.com/", None),   # expression dans l'hôte / le chemin
    ("javascript:void(0)", None), ("data:text/plain,x", None), ("mailto:a@b.c", None),
    ("/a/{id}/b", None), ("/a b", None), ("", None),
])
def test_resolve_endpoint(raw, expected):
    assert surface.resolve_endpoint(raw, BASE) == expected


def test_parse_jsluice_urls_resolves_against_each_files_source(tmp_path):
    lookup = surface.source_lookup([(tmp_path / "1.js", f"{W}/a/one.js"), (tmp_path / "2.js", "https://api.example.com/v1/two.js")])
    rows = [
        {"url": "rel", "filename": str(tmp_path / "1.js")},
        {"url": "rel", "filename": str(tmp_path / "2.js")},
        {"url": "/logo.png", "filename": str(tmp_path / "1.js")},                  # statique
        {"url": "/dup", "filename": str(tmp_path / "1.js")}, {"url": "/dup", "filename": str(tmp_path / "1.js")},
        {"url": 42}, {"nourl": True},
    ]
    urls = surface.parse_jsluice_urls([json.dumps(r) for r in rows] + ["pas du json", ""], lookup)
    assert urls == [f"{W}/a/rel", "https://api.example.com/v1/rel", f"{W}/dup"]


# --------------------------------------------------------------------------- #
# Secrets : masquage et analyse
# --------------------------------------------------------------------------- #

KEY = "AKIAIOSFODNN7EXAMPLE"
SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def test_redaction_never_shows_the_whole_secret():
    assert surface.redact(KEY) == "AKIA…" and surface.redact(SECRET) == "wJal…"
    assert surface.redact("abcdefgh") == "ab…"              # court : moins de 4 caractères visibles
    assert surface.redact("abc") == "…" and surface.redact("") == "…"
    masked = surface.redact_value({"key": KEY, "secret": SECRET, "empty": ""})
    assert masked == "key=AKIA…, secret=wJal…" and KEY not in masked and SECRET not in masked
    assert surface.redact_value(["abcdefghijkl"]) == "abcd…"


def test_secret_parsers_map_files_to_urls_and_never_keep_the_secret_in_the_summary(tmp_path):
    js = store_response(tmp_path, f"{W}/static/app.js")
    lookup = surface.url_lookup(surface.read_katana_index(tmp_path))
    truffle = json.dumps({
        "DetectorName": "AWS", "Raw": SECRET, "Verified": False,
        "SourceMetadata": {"Data": {"Filesystem": {"file": str(js), "line": 7}}},
    })
    (t,) = surface.parse_trufflehog([truffle, "pas du json", json.dumps({"autre": 1})], lookup)
    assert (t.detector, t.url, t.line, t.redacted, t.source) == ("AWS", f"{W}/static/app.js", 7, "wJal…", "trufflehog")

    report = json.dumps([{"RuleID": "aws-access-token", "File": str(js), "Secret": SECRET, "StartLine": 3}])
    (g,) = surface.parse_gitleaks(report, lookup)
    assert (g.detector, g.url, g.line, g.redacted) == ("aws-access-token", f"{W}/static/app.js", 3, "wJal…")
    assert surface.parse_gitleaks("pas du json", lookup) == [] and surface.parse_gitleaks("", lookup) == []

    # jsluice a lu une copie du JS (<sha1>.js) : le nom sans extension retrouve l'URL d'origine.
    row = json.dumps({"kind": "AWSAccessKey", "data": {"key": KEY, "secret": SECRET}, "filename": str(tmp_path / "js" / (js.stem + ".js"))})
    (j,) = surface.parse_jsluice_secrets([row], lookup)
    assert j.url == f"{W}/static/app.js" and j.redacted == "key=AKIA…, secret=wJal…"

    for finding in (t, g, j):
        line = surface.summary_line(finding)
        assert KEY not in line and SECRET not in line and finding.url in line and finding.detector in line


# --------------------------------------------------------------------------- #
# takeover
# --------------------------------------------------------------------------- #


def test_cname_parsing_and_candidate_selection():
    rows = [
        {"host": "WWW.example.com", "cname": ["Target-App.herokudns.com."]},           # tiers → candidat (casse et point final normalisés)
        {"host": "internal.example.com", "cname": ["lb.example.com."]},                # interne → non
        {"host": "sub.example.org", "cname": ["x.example.org"]},                       # autre apex du périmètre → non
        {"host": "mixed.example.com", "cname": ["lb.example.com", "bucket.s3.amazonaws.com"]},
        {"host": "legacy.example.com", "cname": "old.github.io."},                     # cname en chaîne (ancienne version)
        {"host": "ex.example.com", "cname": ["thing.excluded.example.com"]},           # vers une exclusion → on n'y touche pas
        {"host": "plain.example.com"}, {"host": "empty.example.com", "cname": []}, {"cname": ["x.io"]},
    ]
    cnames = surface.parse_cname_rows([json.dumps(r) for r in rows] + ["pas du json"])
    assert cnames["www.example.com"] == ["target-app.herokudns.com"] and "plain.example.com" not in cnames
    candidates = surface.takeover_candidates(cnames, ["example.com", "example.org"], ["excluded.example.com"])
    assert candidates == {
        "www.example.com": ["target-app.herokudns.com"],
        "mixed.example.com": ["bucket.s3.amazonaws.com"],
        "legacy.example.com": ["old.github.io"],
    }
    # « evilexample.com » n'est pas dans le périmètre d'example.com (jamais de contains).
    assert surface.takeover_candidates({"a.example.com": ["evilexample.com"]}, ["example.com"]) == {"a.example.com": ["evilexample.com"]}


def test_subzy_output_parsing():
    rows = [
        {"subdomain": "a.example.com", "status": "vulnerable", "vulnerable": True, "engine": "Heroku", "cname": ["x.herokudns.com"]},
        {"subdomain": "b.example.com", "status": "not vulnerable", "vulnerable": False},
        {"subdomain": "c.example.com", "status": "vulnerable"},
        {"subdomain": "d.example.com", "vulnerable": True},
        {"subdomain": "e.example.com", "status": "error"},
    ]
    parsed = surface.parse_subzy(json.dumps(rows, indent=2))
    assert [r["subdomain"] for r in parsed if surface.is_vulnerable(r)] == ["a.example.com", "c.example.com", "d.example.com"]
    assert surface.parse_subzy("") == [] and surface.parse_subzy("{pas du json") == []
    assert len(surface.parse_subzy("\n".join(json.dumps(r) for r in rows))) == 5        # repli : un objet par ligne
    assert "a.example.com" in surface.takeover_line(rows[0]) and "Heroku" in surface.takeover_line(rows[0])


# --------------------------------------------------------------------------- #
# naabu
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("spec, expected", [
    ("top-1000", ["-top-ports", "1000"]), ("TOP-100", ["-top-ports", "100"]),
    ("80,443,8080-8090", ["-p", "80,443,8080-8090"]), (" 8080 ", ["-p", "8080"]),
])
def test_port_flags_accepts(spec, expected):
    assert surface.port_flags(spec) == expected


@pytest.mark.parametrize("spec", ["full", "1-65535", "1-10000", "top-5000", "", "80;443", "0", "70000", "90-80", "abc", "80,,443"])
def test_port_flags_rejects_full_scans_and_garbage(spec):
    with pytest.raises(ValueError):
        surface.port_flags(spec)


def test_port_flags_full_needs_explicit_permission():
    assert surface.port_flags("full", allow_full=True) == ["-top-ports", "full"]
    assert surface.port_flags("1-65535", allow_full=True) == ["-p", "1-65535"]
    assert surface.port_count(["-top-ports", "1000"]) == 1000 and surface.port_count(["-p", "80,443,8000-8002"]) == 5
    assert surface.port_count(["-top-ports", "full"]) == 65535


def test_naabu_parsing_and_web_candidates():
    lines = [
        json.dumps({"host": "WWW.example.com", "ip": "1.2.3.4", "port": 8080}),
        json.dumps({"host": "www.example.com", "ip": "1.2.3.4", "port": 8080}),         # doublon
        json.dumps({"host": "www.example.com", "port": 443}), json.dumps({"host": "www.example.com", "port": 80}),
        json.dumps({"ip": "5.6.7.8", "port": 9000}),                                    # sans host : repli sur l'ip
        json.dumps({"host": "x.example.com", "port": "abc"}), json.dumps({"host": "x.example.com", "port": 70000}),
        json.dumps({"host": "y.example.com", "port": {"Port": 8443}}), "pas du json",
    ]
    parsed = surface.parse_naabu(lines)
    assert [(h, p) for h, p, _ in parsed] == [
        ("www.example.com", 8080), ("www.example.com", 443), ("www.example.com", 80), ("5.6.7.8", 9000), ("y.example.com", 8443),
    ]
    entries = [f"{h}:{p}" for h, p, _ in parsed]
    assert surface.web_candidates(entries) == ["www.example.com:8080", "5.6.7.8:9000", "y.example.com:8443"]   # ni 80 ni 443
    assert surface.web_candidates(["nohostport", "h:abc", "h:443", "h:80", "h:8080", "h:8080"]) == ["h:8080"]


# --------------------------------------------------------------------------- #
# arjun
# --------------------------------------------------------------------------- #


def test_arjun_targets_priority_first_static_excluded_one_per_signature_and_capped():
    urls = [
        f"{W}/page/1", f"{W}/page/2", f"{W}/logo.png", f"{W}/search?q=a", f"{W}/search?q=b",
        f"{W}/admin/login", f"{W}/zone", f"{W}/api/v1/users?id=3", f"{W}/app.js",
    ]
    # Une représentante par signature (/page/{n}, ?q), statiques exclues, priorité d'abord (ordre d'entrée conservé).
    assert surface.pick_arjun_targets(urls, 100) == [
        f"{W}/admin/login", f"{W}/api/v1/users?id=3", f"{W}/page/1", f"{W}/search?q=a", f"{W}/zone",
    ]
    assert surface.pick_arjun_targets(urls, 3) == [f"{W}/admin/login", f"{W}/api/v1/users?id=3", f"{W}/page/1"]
    assert surface.pick_arjun_targets(urls, 0) == [] and surface.pick_arjun_targets([], 5) == []


def test_arjun_output_and_param_urls():
    found = surface.parse_arjun(json.dumps({
        f"{W}/p": {"params": ["a", "b", "a"], "method": "GET", "headers": {}},
        f"{W}/q?x=orig&a=keep": {"params": ["a", "b"], "method": "GET"},
        f"{W}/none": {"params": [], "method": "GET"},
        f"{W}/dict": {"params": {"k": "v"}},
        "ftp://nope/x": {"params": ["z"]},
    }))
    assert found == {f"{W}/p": ["a", "b"], f"{W}/q?x=orig&a=keep": ["a", "b"], f"{W}/dict": ["k"], "ftp://nope/x": ["z"]}
    assert surface.arjun_param_urls(found) == [
        f"{W}/p?a=1&b=1",
        f"{W}/q?x=orig&a=keep&b=1",         # paramètres existants conservés, a pas dupliqué
        f"{W}/dict?k=1",
    ]                                        # le schéma ftp est écarté
    assert surface.parse_arjun("") == {} and surface.parse_arjun("{pas du json") == {} and surface.parse_arjun("[1]") == {}
    assert surface.param_url(f"{W}/", ["id"]) == f"{W}/?id=1"


# --------------------------------------------------------------------------- #
# Constructeurs de commandes (drapeaux vérifiés dans le code amont)
# --------------------------------------------------------------------------- #


def test_katana_store_flags_only_when_asked(tmp_path, monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(runner, "run_command", rec)
    seeds, out = tmp_path / "seeds.txt", tmp_path / "k.txt"
    args = (seeds, out, 2, "rdn", False, 100, 10, 3000, "10m", False, True, 600)
    modules.stage_katana(*args, store_dir=tmp_path / "responses" / "katana")
    command = rec.calls[0]["command"]
    assert "-store-response" in command and flag(command, "-store-response-dir") == str(tmp_path / "responses" / "katana")
    modules.stage_katana(*args)
    assert not {"-store-response", "-store-response-dir"} & set(rec.calls[1]["command"])


def test_jsluice_command(tmp_path, monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(runner, "run_command", rec)
    files, dest = tmp_path / "files.txt", tmp_path / "out.jsonl"
    files.write_text("a.js\nb.js\n", encoding="utf-8")
    modules.stage_jsluice(files, dest, "urls", 4, 300)
    modules.stage_jsluice(files, dest, "secrets", 2, None)
    urls, secrets = rec.calls
    assert urls["command"] == ["jsluice", "urls", "-c", "4"] and secrets["command"] == ["jsluice", "secrets", "-c", "2"]
    for call in (urls, secrets):
        assert call["silent"] is False and call["stdout_to"] == dest      # jsluice n'a pas de -silent
        assert call["stdin"] == "a.js\nb.js\n"                             # chemins sur l'entrée standard, aucun argument fichier
    assert urls["timeout"] == 300 and secrets["timeout"] is None


def test_trufflehog_never_verifies(tmp_path, monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(runner, "run_command", rec)
    modules.stage_trufflehog(tmp_path / "responses", tmp_path / "out.jsonl", 600)
    (call,) = rec.calls
    command = call["command"]
    assert command[:3] == ["trufflehog", "filesystem", str(tmp_path / "responses")]
    assert "--no-verification" in command and "--json" in command
    # Vérifier = essayer le secret chez son fournisseur = utiliser un identifiant tiers : jamais.
    assert not {"--only-verified", "--results=verified", "--verify"} & set(command)
    assert not any(part.startswith("--results") for part in command)
    assert call["silent"] is False and call["stdout_to"] == tmp_path / "out.jsonl" and call["timeout"] == 600


def test_gitleaks_command_and_legacy_fallback(tmp_path, monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(runner, "run_command", rec)
    report = tmp_path / "r.json"
    modules.stage_gitleaks(tmp_path / "responses", report, 60)
    (call,) = rec.calls                                         # succès : une seule commande
    command = call["command"]
    assert command[:3] == ["gitleaks", "dir", str(tmp_path / "responses")]
    assert flag(command, "--report-format") == "json" and flag(command, "--report-path") == str(report)
    assert flag(command, "--exit-code") == "0" and "--no-banner" in command and call["silent"] is False

    class OldGitleaks(Recorder):
        def __call__(self, command, label, **kwargs):
            super().__call__(command, label, **kwargs)
            return (0, 0.1, "") if command[1] == "detect" else (1, 0.1, "unknown command")

    old = OldGitleaks()
    monkeypatch.setattr(runner, "run_command", old)
    modules.stage_gitleaks(tmp_path / "responses", report, 60)
    assert [c["command"][1] for c in old.calls] == ["dir", "detect"]
    legacy = old.calls[1]["command"]
    assert legacy[:6] == ["gitleaks", "detect", "--no-git", "--source", str(tmp_path / "responses"), "--report-format"] or \
        ("--no-git" in legacy and flag(legacy, "--source") == str(tmp_path / "responses"))


def test_dnsx_cname_command(tmp_path, monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(runner, "run_command", rec)
    modules.stage_dnsx_cname(tmp_path / "02_dnsx.txt", tmp_path / "cname.jsonl", 100)
    command = rec.calls[0]["command"]
    assert command[0] == "dnsx" and flag(command, "-l") == str(tmp_path / "02_dnsx.txt")
    assert {"-cname", "-resp", "-json"} <= set(command) and flag(command, "-o") == str(tmp_path / "cname.jsonl")
    assert rec.calls[0]["silent"] is True                          # dnsx connaît -silent


def test_subzy_command(tmp_path, monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(runner, "run_command", rec)
    modules.stage_subzy(tmp_path / "cand.txt", tmp_path / "out.json", 5, 10, 900)
    (call,) = rec.calls
    command = call["command"]
    assert command[:2] == ["subzy", "run"] and flag(command, "--targets") == str(tmp_path / "cand.txt")
    assert flag(command, "--concurrency") == "5" and flag(command, "--timeout") == "10"
    assert "--hide_fails" in command and "--https" in command and flag(command, "--output") == str(tmp_path / "out.json")
    assert "--verify_ssl" not in command                            # un certificat invalide ne doit pas masquer un dangling
    assert call["silent"] is False and call["timeout"] == 900       # subzy n'a pas de -silent


def test_naabu_command(tmp_path, monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(runner, "run_command", rec)
    modules.stage_naabu(tmp_path / "hosts.txt", tmp_path / "n.jsonl", ["-top-ports", "1000"], 80, 1800)
    modules.stage_naabu(tmp_path / "hosts.txt", tmp_path / "n.jsonl", ["-p", "80,8080-8090"], 20, None)
    top, explicit = rec.calls
    command = top["command"]
    assert command[0] == "naabu" and flag(command, "-list") == str(tmp_path / "hosts.txt")
    assert flag(command, "-top-ports") == "1000" and flag(command, "-rate") == "80"           # débit accordé
    assert "-exclude-cdn" in command and "-json" in command and flag(command, "-o") == str(tmp_path / "n.jsonl")
    assert top["silent"] is True and top["timeout"] == 1800                                     # naabu connaît -silent
    assert flag(explicit["command"], "-p") == "80,8080-8090" and "-top-ports" not in explicit["command"]
    assert flag(explicit["command"], "-rate") == "20"


def test_arjun_command(tmp_path, monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(runner, "run_command", rec)
    modules.stage_arjun(tmp_path / "in.txt", tmp_path / "a.json", 15, 2, 20, False, 1200)
    modules.stage_arjun(tmp_path / "in.txt", tmp_path / "a.json", 15, 2, 20, True, None)
    plain, stable = rec.calls
    command = plain["command"]
    assert command[0] == "arjun" and flag(command, "-i") == str(tmp_path / "in.txt") and flag(command, "-oJ") == str(tmp_path / "a.json")
    assert flag(command, "-m") == "GET" and flag(command, "--rate-limit") == "15"            # débit accordé
    assert flag(command, "-t") == "2" and flag(command, "-T") == "20"
    assert "--stable" not in command and "-d" not in command                                  # lenteur extrême : opt-in seulement
    assert plain["silent"] is False and plain["timeout"] == 1200
    assert "--stable" in stable["command"]
