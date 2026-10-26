"""Tests de `recon_mano merge` (recon_mano.merge) sur un dossier de sortie fabriqué."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from recon_mano.merge import merge_folder

REPO = Path(__file__).resolve().parent.parent


def jsonl(path, rows):
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def lines(path):
    return path.read_text(encoding="utf-8").splitlines()


def make_scan(folder, with_config=True, exclude=()):
    """Dossier comme laissé par un run : seeds vivantes, crawl katana, JSONL httpx #1 et #2."""
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "urls_live.txt").write_text(
        "https://www.example.com/\nhttps://api.example.com/v1\nhttps://evil.net/x\n", encoding="utf-8"
    )
    (folder / "06_katana.txt").write_text(
        "https://www.example.com/a\nhttps://www.example.com/\nhttps://old.example.com/b\nhttps://thirdparty.io/z\n",
        encoding="utf-8",
    )
    jsonl(folder / "05_httpx.jsonl", [{"url": "https://www.example.com/", "status_code": 200}])
    jsonl(folder / "08_httpx2.jsonl", [
        {"url": "https://www.example.com/", "status_code": 200, "title": "Accueil"},
        {"url": "https://www.example.com/a", "status_code": 301},
        {"url": "https://old.example.com/b", "status_code": 403},
        {"url": "https://evil.net/x", "status_code": 200},          # hors périmètre
        {"url": "https://www.example.com/dead", "status_code": 404},
        {"url": "https://www.example.com/crash", "status_code": 500},
    ])
    (folder / "rejected_scope.tsv").write_text("subfinder\tevil.net\tevil.net\n", encoding="utf-8")
    if with_config:
        (folder / "run_config.json").write_text(json.dumps({
            "target": "example.com",
            "scope": {"enabled": True, "apexes": ["example.com"], "excludes": list(exclude)},
            "live_codes": [200, 301, 403],
        }), encoding="utf-8")


def test_merge_rebuilds_everything(tmp_path):
    make_scan(tmp_path)
    result = merge_folder(tmp_path)

    # Carte = seeds + katana, dédoublonnée, hors périmètre écarté.
    assert lines(tmp_path / "all_urls.txt") == [
        "https://www.example.com/",
        "https://api.example.com/v1",
        "https://www.example.com/a",
        "https://old.example.com/b",
    ]
    # Listes finales depuis 08_httpx2.jsonl, scope appliqué.
    assert lines(tmp_path / "urls_all_final.txt") == [
        "https://www.example.com/ [200] [Accueil]",
        "https://www.example.com/a [301]",
        "https://old.example.com/b [403]",
        "https://www.example.com/dead [404]",
        "https://www.example.com/crash [500]",
    ]
    assert lines(tmp_path / "urls_200_final.txt") == ["https://www.example.com/"]
    # Codes vivants de run_config.json : 200, 301, 403 (pas 404/500).
    assert lines(tmp_path / "urls_live_final.txt") == [
        "https://www.example.com/", "https://www.example.com/a", "https://old.example.com/b",
    ]
    assert "www.example.com" in (tmp_path / "urls_tree.html").read_text(encoding="utf-8")

    rebuilt = dict(result.rebuilt)
    assert rebuilt["all_urls.txt"] == 4
    assert rebuilt["urls_200_final.txt"] == 1
    assert rebuilt["urls_tree.html"] == 1
    assert result.from_config and result.scope_apexes == ["example.com"]


def test_merge_uses_exclusions_from_run_config(tmp_path):
    make_scan(tmp_path, exclude=["old.example.com"])
    merge_folder(tmp_path)
    assert "https://old.example.com/b" not in lines(tmp_path / "all_urls.txt")
    assert not any("old.example.com" in l for l in lines(tmp_path / "urls_all_final.txt"))


def test_merge_keeps_earlier_rejections_and_does_not_duplicate_its_own(tmp_path):
    make_scan(tmp_path)
    merge_folder(tmp_path)
    first = lines(tmp_path / "rejected_scope.tsv")
    assert first[0] == "subfinder\tevil.net\tevil.net"            # rejets du run conservés
    assert any(l.startswith("merge\tevil.net\t") for l in first)

    merge_folder(tmp_path)                                         # idempotent
    assert lines(tmp_path / "rejected_scope.tsv") == first


def test_merge_falls_back_to_first_httpx_pass(tmp_path):
    make_scan(tmp_path)
    (tmp_path / "08_httpx2.jsonl").unlink()
    result = merge_folder(tmp_path)
    assert lines(tmp_path / "urls_200_final.txt") == ["https://www.example.com/"]
    assert any("05_httpx.jsonl" in n for n in result.notes)


def test_merge_without_run_config_derives_scope_from_folder_name(tmp_path):
    folder = tmp_path / "example.com"
    make_scan(folder, with_config=False)
    result = merge_folder(folder)
    assert not result.from_config
    assert result.scope_apexes == ["example.com"] and result.scope_enabled
    assert "https://evil.net/x" not in lines(folder / "all_urls.txt")
    # Codes vivants par défaut (200,301,302,307,308,401,403) : le 500 reste exclu.
    assert "https://www.example.com/crash" not in lines(folder / "urls_live_final.txt")
    assert any("run_config.json absent" in n for n in result.notes)


def test_merge_without_config_and_non_domain_folder_disables_scope(tmp_path):
    folder = tmp_path / "sortie"
    make_scan(folder, with_config=False)
    result = merge_folder(folder)
    assert not result.scope_enabled
    assert "https://evil.net/x" in lines(folder / "all_urls.txt")   # rien filtré : on ne devine pas


def test_merge_with_nothing_to_rebuild(tmp_path):
    result = merge_folder(tmp_path)
    assert result.rebuilt == []
    assert not (tmp_path / "all_urls.txt").exists()
    assert len(result.notes) >= 3


def test_merge_legacy_skip_httpx_uses_raw_merged_input(tmp_path):
    (tmp_path / "04_httpx_input.txt").write_text("https://www.example.com/\nhttps://evil.net/\n", encoding="utf-8")
    (tmp_path / "run_config.json").write_text(
        json.dumps({"target": "example.com", "scope": {"enabled": True, "apexes": ["example.com"]}}), encoding="utf-8"
    )
    merge_folder(tmp_path)
    assert lines(tmp_path / "all_urls.txt") == ["https://www.example.com/"]


def _cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "recon_mano", *args], cwd=REPO, capture_output=True, text=True, encoding="utf-8",
    )


def test_merge_cli_subcommand(tmp_path):
    make_scan(tmp_path)
    proc = _cli("merge", str(tmp_path))
    assert proc.returncode == 0, proc.stderr
    assert "all_urls.txt" in proc.stdout and "urls_200_final.txt" in proc.stdout
    assert (tmp_path / "urls_tree.html").exists()


def test_merge_cli_errors(tmp_path):
    assert _cli("merge").returncode == 2
    assert _cli("merge", str(tmp_path / "absent")).returncode == 1
