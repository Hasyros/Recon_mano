"""crt.sh : analyse des réponses, nouveaux essais, module dans le DAG — urlopen est toujours simulé."""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request

import pytest

from recon_mano import crtsh
from recon_mano.crtsh import CrtshError, clean_name, fetch_domain, parse_payload
from recon_mano.pipeline import Status

from .test_modules import FakeCrtsh, FakeResponse, lines, run_dag, statuses


def http_error(code):
    return urllib.error.HTTPError("https://crt.sh/", code, "err", {}, None)


# --------------------------------------------------------------------------- #
# Analyse
# --------------------------------------------------------------------------- #


def test_clean_name_rules():
    assert clean_name("WWW.Example.COM") == "www.example.com"
    assert clean_name("*.example.com") == "example.com"
    assert clean_name("*.*.example.com") == "example.com"
    assert clean_name("api.example.com.") == "api.example.com"
    assert clean_name("  mail.example.com  ") == "mail.example.com"
    assert clean_name("_dmarc.example.com") == "_dmarc.example.com"
    for bad in ("", "   ", "admin@example.com", "foo.*.example.com", "localhost", "10.0.0.1",
                "with space.example.com", "-bad.example.com", "bad-.example.com", "a..example.com",
                "a" * 64 + ".example.com", "x." * 130 + "com"):
        assert clean_name(bad) == "", bad


def test_parse_payload_multiline_wildcards_emails_duplicates():
    payload = [
        {"name_value": "example.com\n*.example.com\nwww.example.com"},
        {"name_value": "WWW.example.com\nadmin@example.com\napi.example.com"},
        {"name_value": "*.dev.example.com"},
        {"name_value": "10.1.2.3"},
        {"name_value": None},
        {"common_name": "ignored.example.com"},
        "pas un objet",
    ]
    assert parse_payload(payload) == ["api.example.com", "dev.example.com", "example.com", "www.example.com"]
    assert parse_payload([]) == []
    with pytest.raises(CrtshError):
        parse_payload({"error": "x"})


# --------------------------------------------------------------------------- #
# Requêtes et nouveaux essais (urlopen simulé)
# --------------------------------------------------------------------------- #


def test_request_url_and_headers(monkeypatch):
    fake = FakeCrtsh(names=["a.example.com"])
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    assert crtsh.fetch_once("example.com", 42) == ["a.example.com"]
    (url, timeout), = fake.requests
    assert url == "https://crt.sh/?q=%25.example.com&output=json" and timeout == 42


def test_5xx_then_success_is_retried_with_backoff(monkeypatch):
    fake = FakeCrtsh(script=[http_error(503), http_error(502), [{"name_value": "ok.example.com"}]])
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    slept, notices = [], []
    names = fetch_domain("example.com", retries=2, backoff=5, sleep=slept.append, notice=notices.append)
    assert names == ["ok.example.com"]
    assert len(fake.requests) == 3
    assert slept == [5, 10]                       # le délai double à chaque essai
    assert len(notices) == 2 and "HTTP 503" in notices[0]


def test_timeouts_exhaust_retries_then_fail(monkeypatch):
    fake = FakeCrtsh(script=[socket.timeout("timed out")])
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    slept = []
    with pytest.raises(CrtshError, match="délai.*3 essais"):
        fetch_domain("example.com", request_timeout=7, retries=2, backoff=1, sleep=slept.append)
    assert len(fake.requests) == 3 and slept == [1, 2]


def test_url_error_and_truncated_json_are_retryable(monkeypatch):
    fake = FakeCrtsh(script=[
        urllib.error.URLError("connection refused"), b'[{"name_value": "a.exa', [{"name_value": "a.example.com"}],
    ])
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    assert fetch_domain("example.com", sleep=lambda s: None) == ["a.example.com"]
    assert len(fake.requests) == 3


def test_urlerror_wrapping_a_timeout_reads_as_timeout(monkeypatch):
    fake = FakeCrtsh(script=[urllib.error.URLError(socket.timeout("timed out"))])
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    with pytest.raises(CrtshError, match="délai"):
        fetch_domain("example.com", retries=0, sleep=lambda s: None)


def test_4xx_is_not_retried_except_429(monkeypatch):
    fake = FakeCrtsh(script=[http_error(400)])
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    with pytest.raises(CrtshError, match="HTTP 400"):
        fetch_domain("example.com", sleep=lambda s: None)
    assert len(fake.requests) == 1

    fake = FakeCrtsh(script=[http_error(429), [{"name_value": "a.example.com"}]])
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    assert fetch_domain("example.com", sleep=lambda s: None) == ["a.example.com"]


def test_no_retry_once_the_module_deadline_passed(monkeypatch):
    fake = FakeCrtsh(script=[http_error(503)])
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    state = {"n": 0}

    def expired():
        state["n"] += 1
        return state["n"] > 1                    # la 2e vérification (avant le 2e essai) est trop tard

    with pytest.raises(CrtshError, match="échéance"):
        fetch_domain("example.com", retries=2, backoff=0, sleep=lambda s: None, expired=expired)
    assert len(fake.requests) == 1


def test_real_urlopen_is_blocked_in_tests():
    with pytest.raises(AssertionError, match="réseau interdit"):
        urllib.request.urlopen("https://crt.sh/")


# --------------------------------------------------------------------------- #
# Module dans le DAG
# --------------------------------------------------------------------------- #


def test_module_filters_scope_and_logs_rejections(tmp_path, monkeypatch):
    payload = [
        {"name_value": "www.example.com\n*.example.com\nadmin@example.com"},
        {"name_value": "WWW.example.com\nshop.example.com\nevil.net\nnotexample.com\nexample.com.evil.net"},
    ]
    fake = FakeCrtsh(script=[payload])
    scheduler, ctx, _ = run_dag(tmp_path, monkeypatch, crtsh_fake=fake)
    assert statuses(scheduler)["crtsh"] is Status.DONE
    assert lines(tmp_path / "01b_crtsh.txt") == ["example.com", "shop.example.com", "www.example.com"]
    rejected = [r for r in lines(tmp_path / "rejected_scope.tsv") if r.startswith("crtsh\t")]
    assert {r.split("\t")[1] for r in rejected} == {"evil.net", "notexample.com", "example.com.evil.net"}
    assert [url for url, _ in fake.requests] == ["https://crt.sh/?q=%25.example.com&output=json"]


def test_one_request_per_scope_apex(tmp_path, monkeypatch):
    fake = FakeCrtsh(script=[[{"name_value": "a.example.com\nb.example.org\nc.other.net"}]])
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, crtsh_fake=fake, scope=("example.com", "example.org"))
    assert sorted(url for url, _ in fake.requests) == [
        "https://crt.sh/?q=%25.example.com&output=json", "https://crt.sh/?q=%25.example.org&output=json",
    ]
    assert lines(tmp_path / "01b_crtsh.txt") == ["a.example.com", "b.example.org"]   # c.other.net hors périmètre


def test_request_timeout_option_is_used(tmp_path, monkeypatch):
    fake = FakeCrtsh()
    run_dag(tmp_path, monkeypatch, crtsh_fake=fake, crtsh_timeout=33)
    assert fake.requests[0][1] == 33


def test_timeout_then_failure_fails_the_module_and_the_pipeline_continues(tmp_path, monkeypatch):
    fake = FakeCrtsh(script=[socket.timeout("timed out")])
    scheduler, _, tools = run_dag(tmp_path, monkeypatch, crtsh_fake=fake)
    st = statuses(scheduler)
    assert st["crtsh"] is Status.FAILED and "délai" in scheduler.records["crtsh"].note
    assert len(fake.requests) == 3                                 # 1 essai + 2 nouveaux
    assert st["subdomains"] is Status.DONE and st["httpx"] is Status.DONE and st["httpx2"] is Status.DONE
    assert "www.example.com" in lines(tmp_path / "01_subdomains.txt")         # les autres sources suffisent
    assert not (tmp_path / "01b_crtsh.txt").exists()


def test_5xx_then_success_through_the_module(tmp_path, monkeypatch):
    fake = FakeCrtsh(script=[http_error(504), [{"name_value": "late.example.com"}]])
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, crtsh_fake=fake)
    assert statuses(scheduler)["crtsh"] is Status.DONE and len(fake.requests) == 2
    assert lines(tmp_path / "01b_crtsh.txt") == ["late.example.com"]


def test_one_apex_failing_does_not_fail_the_module(tmp_path, monkeypatch):
    class PerApex(FakeCrtsh):
        def __call__(self, request, timeout=None):
            self.requests.append((request.full_url, timeout))
            if "example.org" in request.full_url:
                raise http_error(500)
            return FakeResponse(json.dumps([{"name_value": "a.example.com"}]).encode())

    scheduler, _, _ = run_dag(tmp_path, monkeypatch, crtsh_fake=PerApex(), scope=("example.com", "example.org"), crtsh_retries=0)
    rec = scheduler.records["crtsh"]
    assert rec.status is Status.DONE and rec.note == "1/2 apex en échec"
    assert lines(tmp_path / "01b_crtsh.txt") == ["a.example.com"]


def test_empty_answer_is_a_valid_empty_result(tmp_path, monkeypatch):
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, crtsh_fake=FakeCrtsh(script=[[]]))
    assert scheduler.records["crtsh"].status is Status.DONE and scheduler.records["crtsh"].count == 0


def test_disabled_by_flag_never_calls_crtsh(tmp_path, monkeypatch):
    fake = FakeCrtsh()
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, crtsh_fake=fake, crtsh=False)
    assert statuses(scheduler)["crtsh"] is Status.SKIPPED and "option" in scheduler.records["crtsh"].note
    assert fake.requests == [] and not (tmp_path / "01b_crtsh.txt").exists()


def test_crtsh_needs_no_binary(tmp_path, monkeypatch):
    # Même sans aucun binaire optionnel, crtsh tourne : c'est du Python.
    scheduler, _, _ = run_dag(tmp_path, monkeypatch, missing={"amass", "gau", "waybackurls", "subfinder"})
    assert statuses(scheduler)["crtsh"] is Status.DONE
    assert statuses(scheduler)["subfinder"] is Status.DISABLED
    assert "www.example.com" in lines(tmp_path / "01_subdomains.txt")
