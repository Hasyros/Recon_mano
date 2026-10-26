"""Tests du filtre de vivacité (recon_mano.liveness)."""

from __future__ import annotations

import json

import pytest

from recon_mano.liveness import (
    DEFAULT_LIVE_CODES,
    clean_live_urls,
    filter_live,
    iter_httpx_rows,
    parse_codes,
    split_httpx_output,
)


def _jsonl(path, rows):
    path.write_text("\n".join(r if isinstance(r, str) else json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def _read(path):
    return path.read_text(encoding="utf-8").splitlines()


# --------------------------------------------------------------------------- #
# parse_codes
# --------------------------------------------------------------------------- #


def test_parse_codes_default():
    assert parse_codes(DEFAULT_LIVE_CODES) == {200, 301, 302, 307, 308, 401, 403}


def test_parse_codes_tolerates_spaces_and_empties():
    assert parse_codes(" 200, 404 ,, 500 503") == {200, 404, 500, 503}
    assert parse_codes("") == set()


def test_parse_codes_invalid():
    with pytest.raises(ValueError):
        parse_codes("200,abc")


# --------------------------------------------------------------------------- #
# filter_live
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("code", [200, 301, 302, 307, 308, 401, 403])
def test_live_codes_in(code):
    rows = [{"url": "https://a.example.com", "status_code": code}]
    assert filter_live(rows, parse_codes(DEFAULT_LIVE_CODES)) == ["https://a.example.com"]


@pytest.mark.parametrize("code", [404, 500, 502, 503, 204, 405])
def test_live_codes_out(code):
    rows = [{"url": "https://a.example.com", "status_code": code}]
    assert filter_live(rows, parse_codes(DEFAULT_LIVE_CODES)) == []


def test_filter_live_custom_codes_and_dedupe():
    rows = [
        {"url": "https://a.example.com", "status_code": 500},
        {"url": "https://a.example.com", "status_code": 500},
        {"url": "https://b.example.com", "status_code": 200},
    ]
    assert filter_live(rows, {500}) == ["https://a.example.com"]


def test_filter_live_missing_status_or_url():
    rows = [{"url": "https://a.example.com"}, {"status_code": 200}, {"url": "", "status_code": 200}]
    assert filter_live(rows, {200}) == []


def test_filter_live_input_fallback():
    assert filter_live([{"input": "https://a.example.com", "status_code": 200}], {200}) == ["https://a.example.com"]


# --------------------------------------------------------------------------- #
# iter_httpx_rows
# --------------------------------------------------------------------------- #


def test_iter_httpx_rows_skips_bad_lines():
    lines = ['{"url": "https://a", "status_code": 200}', "{pas du json", "42", "[]", '"str"']
    assert list(iter_httpx_rows(lines)) == [{"url": "https://a", "status_code": 200}]


# --------------------------------------------------------------------------- #
# split_httpx_output
# --------------------------------------------------------------------------- #

ROWS = [
    {"url": "https://ok.example.com", "status_code": 200, "content_length": 1234,
     "title": "Accueil\nSite", "tech": ["Nginx", "PHP"]},
    {"url": "https://moved.example.com", "status_code": 301, "content_length": 0},
    {"url": "https://tmp.example.com", "status_code": 302},
    {"url": "https://api.example.com", "status_code": 401, "title": "Unauthorized"},
    {"url": "https://admin.example.com", "status_code": 403},
    {"url": "https://gone.example.com", "status_code": 404},
    {"url": "https://crash.example.com", "status_code": 500},
    {"url": "https://bad-gw.example.com", "status_code": 502},
]


def test_split_outputs(tmp_path):
    src, all_f, ok_f, live_f = (tmp_path / n for n in ("h.jsonl", "all.txt", "ok.txt", "live.txt"))
    _jsonl(src, ROWS)

    total, alive, live = split_httpx_output(src, all_f, ok_f, live_f)

    assert (total, alive, live) == (8, 1, 5)
    assert _read(ok_f) == ["https://ok.example.com"]
    assert _read(live_f) == [
        "https://ok.example.com",
        "https://moved.example.com",
        "https://tmp.example.com",
        "https://api.example.com",
        "https://admin.example.com",
    ]
    live_text = live_f.read_text(encoding="utf-8")
    for dead in ("gone", "crash", "bad-gw"):
        assert dead not in live_text


def test_annotated_format_unchanged(tmp_path):
    src, all_f, ok_f = (tmp_path / n for n in ("h.jsonl", "all.txt", "ok.txt"))
    _jsonl(src, ROWS)
    split_httpx_output(src, all_f, ok_f)
    lines = _read(all_f)
    assert lines[0] == "https://ok.example.com [200] [1234] [Accueil Site] [Nginx,PHP]"
    assert lines[1] == "https://moved.example.com [301] [0]"
    assert lines[2] == "https://tmp.example.com [302]"
    assert lines[3] == "https://api.example.com [401] [Unauthorized]"
    assert len(lines) == 8  # tous les résultats, 404/5xx compris


def test_split_without_live_file_still_counts(tmp_path):
    src = tmp_path / "h.jsonl"
    _jsonl(src, ROWS)
    total, alive, live = split_httpx_output(src, tmp_path / "a.txt", tmp_path / "o.txt")
    assert (total, alive, live) == (8, 1, 5)
    assert not (tmp_path / "live.txt").exists()


def test_split_custom_live_codes(tmp_path):
    src, live_f = tmp_path / "h.jsonl", tmp_path / "live.txt"
    _jsonl(src, ROWS)
    _, _, live = split_httpx_output(src, tmp_path / "a.txt", tmp_path / "o.txt", live_f, {500, 502})
    assert live == 2
    assert _read(live_f) == ["https://crash.example.com", "https://bad-gw.example.com"]


def test_split_skips_malformed_lines(tmp_path):
    src, all_f, ok_f, live_f = (tmp_path / n for n in ("h.jsonl", "all.txt", "ok.txt", "live.txt"))
    _jsonl(src, [
        "{cassé",
        {"url": "https://a.example.com", "status_code": 200},
        "",
        "null",
        {"status_code": 200},  # ni url ni input
        '{"url": "https://b.example.com", "status_code": 404}',
    ])
    assert split_httpx_output(src, all_f, ok_f, live_f) == (2, 1, 1)
    assert _read(live_f) == ["https://a.example.com"]


def test_split_input_fallback_when_url_missing(tmp_path):
    src, all_f, ok_f, live_f = (tmp_path / n for n in ("h.jsonl", "all.txt", "ok.txt", "live.txt"))
    _jsonl(src, [{"input": "https://a.example.com", "status_code": 200}])
    assert split_httpx_output(src, all_f, ok_f, live_f) == (1, 1, 1)
    assert _read(all_f) == ["https://a.example.com [200]"]
    assert _read(live_f) == ["https://a.example.com"]


def test_split_missing_status_is_not_live(tmp_path):
    src, all_f, ok_f, live_f = (tmp_path / n for n in ("h.jsonl", "all.txt", "ok.txt", "live.txt"))
    _jsonl(src, [{"url": "https://a.example.com"}])
    assert split_httpx_output(src, all_f, ok_f, live_f) == (1, 0, 0)
    assert _read(all_f) == ["https://a.example.com [-]"]


def test_split_missing_jsonl(tmp_path):
    assert split_httpx_output(tmp_path / "absent.jsonl", tmp_path / "a.txt", tmp_path / "o.txt", tmp_path / "l.txt") == (0, 0, 0)


# --------------------------------------------------------------------------- #
# clean_live_urls (inchangé, déplacé)
# --------------------------------------------------------------------------- #


def test_clean_live_urls(tmp_path):
    all_f, fallback = tmp_path / "urls_all.txt", tmp_path / "all_urls.txt"
    all_f.write_text("https://a.example.com [200] [Titre]\nnot-a-url [200]\n", encoding="utf-8")
    fallback.write_text("https://fallback.example.com\n", encoding="utf-8")
    assert clean_live_urls(all_f, fallback) == ["https://a.example.com"]
    all_f.write_text("", encoding="utf-8")
    assert clean_live_urls(all_f, fallback) == ["https://fallback.example.com"]
