"""Tests du périmètre strict (recon_mano.scope)."""

from __future__ import annotations

import pytest

from recon_mano.io_utils import read_lines
from recon_mano.scope import ScopeFilter, host_of, in_scope, parse_domains, scope_urls

APEX = "example.com"


# --------------------------------------------------------------------------- #
# host_of
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("example.com", "example.com"),
        ("EXAMPLE.com.", "example.com"),
        ("example.com:8443", "example.com"),
        ("https://Sub.Example.COM:8443/a/b?x=1#frag", "sub.example.com"),
        ("https://user:pass@example.com/x", "example.com"),
        ("example.com/path?q=1", "example.com"),
        ("example.com?q=1", "example.com"),
        ("http://[::1]:8080/x", "::1"),
        ("https://example.com/ [200] [Titre]", "example.com"),
        ("", ""),
        ("   ", ""),
        ("http://", ""),
        ("http://[::1", ""),
    ],
)
def test_host_of(raw, expected):
    assert host_of(raw) == expected


def test_host_of_userinfo_trick_returns_real_host():
    # example.com n'est ici que le userinfo : l'hôte réel est evil.net.
    assert host_of("http://example.com@evil.net/") == "evil.net"


def test_host_of_backslash_trick_is_rejected():
    assert host_of("http://evil.com\\@example.com/") == ""


# --------------------------------------------------------------------------- #
# in_scope
# --------------------------------------------------------------------------- #


def test_exact_apex():
    assert in_scope("example.com", [APEX])


def test_subdomain_and_deep_subdomain():
    assert in_scope("api.example.com", [APEX])
    assert in_scope("a.b.c.example.com", [APEX])


@pytest.mark.parametrize(
    "host",
    [
        "notexample.com",
        "evilexample.com",
        "example.com.evil.net",
        "https://example.com.evil.net/login",
        "example.co",
        "example.com.attacker.example.org",
        "example.community",
    ],
)
def test_lookalikes_are_out(host):
    assert not in_scope(host, [APEX])


def test_userinfo_cannot_spoof_scope():
    assert not in_scope("https://example.com@evil.net/", [APEX])
    assert not in_scope("https://evil.net/?next=example.com", [APEX])
    assert not in_scope("https://evil.net/example.com", [APEX])


def test_url_with_port_userinfo_path_query():
    assert in_scope("https://admin:pw@dev.example.com:8443/a/b?x=1#f", [APEX])
    assert in_scope("dev.example.com:8080", [APEX])


def test_uppercase_and_trailing_dot():
    assert in_scope("API.EXAMPLE.COM.", [APEX])
    assert in_scope("api.example.com", ["EXAMPLE.COM."])


def test_annotated_line_uses_first_token():
    assert in_scope("https://app.example.com/login [200] [Mon titre example.net]", [APEX])
    assert not in_scope("https://evil.net/ [200] [example.com]", [APEX])


def test_multiple_apexes():
    apexes = ["devinci.fr", "esilv.fr"]
    assert in_scope("www.devinci.fr", apexes)
    assert in_scope("esilv.fr", apexes)
    assert not in_scope("emlv.fr", apexes)


def test_apexes_as_single_string():
    assert in_scope("a.example.com", "example.com")
    assert in_scope("x.esilv.fr", "devinci.fr, *.esilv.fr")
    assert not in_scope("a.example.org", "example.com")


def test_apex_with_wildcard_prefix_is_normalized():
    assert in_scope("a.example.com", ["*.example.com"])
    assert in_scope("example.com", ["*.example.com"])


@pytest.mark.parametrize("raw", ["", "   ", "garbage line with spaces", "://", "///", "[]"])
def test_empty_and_garbage_are_out(raw):
    assert not in_scope(raw, [APEX])


def test_no_apexes_means_nothing_in_scope():
    assert not in_scope("example.com", [])
    assert not in_scope("example.com", ["", " "])


def test_excludes_exact_and_subdomain():
    ex = ["admin.example.com"]
    assert not in_scope("admin.example.com", [APEX], ex)
    assert not in_scope("x.admin.example.com", [APEX], ex)
    assert not in_scope("https://x.y.admin.example.com:8443/a", [APEX], ex)
    assert in_scope("www.example.com", [APEX], ex)
    # un frère qui partage le suffixe de texte n'est pas exclu
    assert in_scope("notadmin.example.com", [APEX], ex)


def test_excludes_as_string_and_apex_itself():
    assert not in_scope("a.example.com", [APEX], "example.com")
    assert not in_scope("b.example.com", [APEX], "a.example.com, b.example.com")
    assert in_scope("c.example.com", [APEX], "a.example.com, b.example.com")


def test_scope_urls():
    lines = ["https://a.example.com/x", "https://evil.net/", "b.example.com", "", "notexample.com"]
    assert scope_urls(lines, [APEX]) == ["https://a.example.com/x", "b.example.com"]
    assert scope_urls(lines, [APEX], ["b.example.com"]) == ["https://a.example.com/x"]


# --------------------------------------------------------------------------- #
# parse_domains
# --------------------------------------------------------------------------- #


def test_parse_domains_basic():
    assert parse_domains("devinci.fr,esilv.fr") == ["devinci.fr", "esilv.fr"]


def test_parse_domains_wildcard_case_dots_spaces_dedupe():
    spec = " *.DevInci.fr , esilv.fr.  ,devinci.fr\n .emlv.fr, "
    assert parse_domains(spec) == ["devinci.fr", "esilv.fr", "emlv.fr"]


def test_parse_domains_empty():
    assert parse_domains("") == []
    assert parse_domains(" , ,") == []
    assert parse_domains("*.") == []


def test_parse_domains_accepts_url():
    assert parse_domains("https://Example.com/path") == ["example.com"]


# --------------------------------------------------------------------------- #
# ScopeFilter
# --------------------------------------------------------------------------- #


def test_filter_counters_and_log(tmp_path):
    log = tmp_path / "rejected_scope.tsv"
    scope = ScopeFilter([APEX], ["admin.example.com"], log)
    lines = [
        "www.example.com",
        "api.apple.com",
        "https://evil.net/?x=example.com",
        "https://admin.example.com/login",
        "https://shop.example.com/ [200] [Boutique]",
        "",
    ]
    kept = scope.filter(lines, "urlfinder")

    assert kept == ["www.example.com", "https://shop.example.com/ [200] [Boutique]"]
    assert scope.rejected["urlfinder"] == 3
    assert scope.total_rejected == 3

    rows = [row.split("\t") for row in log.read_text(encoding="utf-8").splitlines()]
    assert rows == [
        ["urlfinder", "api.apple.com", "api.apple.com"],
        ["urlfinder", "evil.net", "https://evil.net/?x=example.com"],
        ["urlfinder", "admin.example.com", "https://admin.example.com/login"],
    ]


def test_counters_accumulate_per_stage(tmp_path):
    scope = ScopeFilter([APEX], reject_log=tmp_path / "r.tsv")
    scope.filter(["a.other.org"], "dnsx")
    scope.filter(["b.other.org", "c.other.org"], "katana")
    scope.filter(["d.other.org"], "katana")
    assert dict(scope.rejected) == {"dnsx": 1, "katana": 3}
    assert scope.total_rejected == 4
    stages = [row.split("\t")[0] for row in (tmp_path / "r.tsv").read_text(encoding="utf-8").splitlines()]
    assert stages == ["dnsx", "katana", "katana", "katana"]


def test_garbage_line_is_rejected_with_empty_host(tmp_path):
    log = tmp_path / "r.tsv"
    scope = ScopeFilter([APEX], reject_log=log)
    assert scope.filter(["http://", "ok.example.com"], "dnsx") == ["ok.example.com"]
    assert log.read_text(encoding="utf-8") == "dnsx\t\thttp://\n"


def test_log_is_truncated_at_each_run(tmp_path):
    log = tmp_path / "rejected_scope.tsv"
    first = ScopeFilter([APEX], reject_log=log)
    first.filter(["x.other.org"], "dnsx")
    assert log.read_text(encoding="utf-8")

    second = ScopeFilter([APEX], reject_log=log)  # nouveau run
    assert log.read_text(encoding="utf-8") == ""
    second.filter(["y.other.org"], "dnsx")
    assert log.read_text(encoding="utf-8").count("\n") == 1


def test_disabled_mode_changes_nothing(tmp_path):
    log = tmp_path / "rejected_scope.tsv"
    log.write_text("dnsx\told\told\n", encoding="utf-8")  # reste d'un run précédent
    scope = ScopeFilter([APEX], ["admin.example.com"], log, enabled=False)

    lines = ["api.apple.com", "admin.example.com", "www.example.com"]
    assert scope.filter(lines, "dnsx") == lines
    assert scope.total_rejected == 0
    assert not log.exists()  # journal périmé supprimé, rien de nouveau écrit

    src = tmp_path / "hosts.txt"
    src.write_text("api.apple.com\napi.apple.com\nwww.example.com\n", encoding="utf-8")
    assert scope.filter_file(src, "dnsx") == (3, 0)
    assert src.read_text(encoding="utf-8") == "api.apple.com\napi.apple.com\nwww.example.com\n"  # intact


def test_filter_file_rewrites_in_place(tmp_path):
    log = tmp_path / "rejected_scope.tsv"
    scope = ScopeFilter([APEX], reject_log=log)
    src = tmp_path / "01_subfinder.txt"
    src.write_text(
        "a.example.com\napi.apple.com\na.example.com\nb.example.com\nexample.com.evil.net\n",
        encoding="utf-8",
    )

    kept, rejected = scope.filter_file(src, "subfinder")

    assert (kept, rejected) == (2, 2)  # doublon fusionné, 2 hors scope
    assert src.read_text(encoding="utf-8") == "a.example.com\nb.example.com\n"
    assert scope.rejected["subfinder"] == 2
    assert [row.split("\t")[1] for row in log.read_text(encoding="utf-8").splitlines()] == [
        "api.apple.com",
        "example.com.evil.net",
    ]


def test_filter_file_all_rejected_leaves_empty_file(tmp_path):
    scope = ScopeFilter([APEX], reject_log=tmp_path / "r.tsv")
    src = tmp_path / "x.txt"
    src.write_text("a.other.org\n", encoding="utf-8")
    assert scope.filter_file(src, "dnsx") == (0, 1)
    assert src.read_text(encoding="utf-8") == ""
    assert read_lines(src) == []


def test_filter_file_missing_file(tmp_path):
    scope = ScopeFilter([APEX], reject_log=tmp_path / "r.tsv")
    assert scope.filter_file(tmp_path / "absent.txt", "dnsx") == (0, 0)
    assert not (tmp_path / "absent.txt").exists()


def test_filter_without_log_still_counts():
    scope = ScopeFilter([APEX])
    assert scope.filter(["a.other.org", "ok.example.com"], "dnsx") == ["ok.example.com"]
    assert scope.total_rejected == 1


def test_tabs_in_rejected_line_do_not_break_tsv(tmp_path):
    log = tmp_path / "r.tsv"
    scope = ScopeFilter([APEX], reject_log=log)
    scope.filter(["evil.net\t[titre\tavec tabs]"], "httpx")
    assert len(log.read_text(encoding="utf-8").splitlines()[0].split("\t")) == 3
