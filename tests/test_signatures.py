"""Signatures d'URL, URLs représentantes, détection statique / prioritaire (+ gf mocké)."""

from __future__ import annotations

import shutil

import pytest

from recon_mano import runner, signatures
from recon_mano.signatures import (
    gf_matches,
    has_params,
    has_suspicious_param,
    host_port,
    is_priority,
    is_static,
    representatives,
    select_priority,
    signature,
    template_segment,
)


# --------------------------------------------------------------------------- #
# Templating des segments
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("segment, expected", [
    ("123", "{n}"),
    ("0", "{n}"),
    ("550e8400-e29b-41d4-a716-446655440000", "{uuid}"),
    ("550E8400-E29B-41D4-A716-446655440000", "{uuid}"),
    ("2024-03-15", "{date}"),
    ("d41d8cd98f00b204e9800998ecf8427e", "{hash}"),                                   # md5
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "{hash}"),                           # sha1
    ("deadbeefdeadbeef", "{hash}"),                                                   # 16 hex : limite basse
    ("deadbeefdeadbee", "deadbeefdeadbee"),                                           # 15 : trop court
    ("aB3dE5fG7hJ9kL1mN3pQ5rS7tU", "{tok}"),                                         # 26 car., mixte
    ("x9Fq2LmZ8vTn4RcW1yBk7HsD", "{tok}"),                                          # 24 car. pile
    ("api", "api"),
    ("v1", "v1"),
    ("users", "users"),
    ("2024-13-45", "2024-13-45"),                                                     # pas une vraie date
    ("mon-super-article-de-blog-2024", "mon-super-article-de-blog-2024"),             # slug : porte du sens
    ("abcdefghijklmnopqrstuvwxyzabc", "abcdefghijklmnopqrstuvwxyzabc"),               # long mais sans chiffre
])
def test_template_segment(segment, expected):
    assert template_segment(segment) == expected


def test_signature_templates_each_kind_in_a_path():
    url = "https://Shop.Example.com/p/42/d41d8cd98f00b204e9800998ecf8427e/2024-03-15/550e8400-e29b-41d4-a716-446655440000/aB3dE5fG7hJ9kL1mN3pQ5rS7tU"
    assert signature(url) == "shop.example.com/p/{n}/{hash}/{date}/{uuid}/{tok}"


def test_same_path_different_values_same_signature():
    assert signature("https://a.com/produit/1") == signature("https://a.com/produit/9000")
    assert signature("https://a.com/s?q=chat&page=2") == signature("https://a.com/s?page=9&q=chien")


def test_param_names_sorted_unique_without_values():
    assert signature("https://a.com/s?b=1&a=2&b=3") == "a.com/s?a&b"
    assert signature("https://a.com/s?z&a=") == "a.com/s?a&z"      # sans valeur / valeur vide
    assert signature("https://a.com/s") == "a.com/s"


def test_different_param_set_different_signature():
    assert signature("https://a.com/s?q=1") != signature("https://a.com/s?q=1&page=2")
    assert signature("https://a.com/s?q=1") != signature("https://a.com/s")


def test_port_is_part_of_the_signature_but_default_ports_are_not():
    assert signature("https://a.com:8443/x") != signature("https://a.com/x")
    assert signature("https://a.com:8443/x") == "a.com:8443/x"
    assert signature("https://a.com:443/x") == signature("https://a.com/x")
    assert signature("http://a.com:80/x") == signature("http://a.com/x")
    assert signature("http://a.com:8080/x") != signature("http://a.com:8081/x")


def test_scheme_is_ignored():
    assert signature("http://a.com/x?id=1") == signature("https://a.com/x?id=2")


def test_trailing_slash_and_root_normalized():
    assert signature("https://a.com/x/") == signature("https://a.com/x")
    assert signature("https://a.com") == signature("https://a.com/")
    assert signature("https://a.com//x///y/") == "a.com/x/y"


def test_fragment_ignored_and_host_lowercased():
    assert signature("https://A.COM/x#frag") == signature("https://a.com/x")


def test_path_case_is_kept():
    assert signature("https://a.com/Admin") != signature("https://a.com/admin")


def test_host_port_helper():
    assert host_port("https://A.com:8443/x") == "a.com:8443"
    assert host_port("a.com") == "a.com"                 # champ `input` de httpx
    assert host_port("a.com:8080") == "a.com:8080"
    assert host_port("https://[::1]:8443/") == "[::1]:8443"
    assert host_port("") == ""


# --------------------------------------------------------------------------- #
# Statique
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("url", [
    "https://a.com/app.js", "https://a.com/app.js?v=3", "https://a.com/css/site.CSS", "https://a.com/i/logo.png",
    "https://a.com/fonts/x.woff2", "https://a.com/app.js.map", "https://a.com/v.mp4", "https://a.com/doc.pdf",
    "https://a.com/dl/site.zip", "https://a.com/dl/site.tar", "https://a.com/dl/site.gz", "https://a.com/dl/s.tgz",
    "https://a.com/dl/s.rar", "https://a.com/dl/s.7z", "https://a.com/f.doc", "https://a.com/f.docx",
    "https://a.com/f.xls", "https://a.com/f.xlsx", "https://a.com/f.ppt", "https://a.com/f.pptx",
])
def test_static_urls(url):
    assert is_static(url)


@pytest.mark.parametrize("url", [
    "https://a.com/", "https://a.com/api/users", "https://a.com/index.php", "https://a.com/data.json",
    "https://a.com/page.html", "https://a.com/v1.2/users", "https://a.com/dir.js/handler", "https://a.com/x?file=a.png",
])
def test_dynamic_urls(url):
    assert not is_static(url)


# --------------------------------------------------------------------------- #
# Représentants
# --------------------------------------------------------------------------- #


def test_representatives_keep_first_k_per_signature_in_input_order():
    urls = [f"https://a.com/p/{i}" for i in range(1, 8)] + ["https://a.com/about", "https://a.com/q?x=1"]
    assert representatives(urls, k=2) == ["https://a.com/p/1", "https://a.com/p/2", "https://a.com/about", "https://a.com/q?x=1"]
    assert representatives(urls, k=1)[0] == "https://a.com/p/1" and len(representatives(urls, k=1)) == 3


def test_representatives_order_is_input_order_across_signatures():
    urls = ["https://a.com/b", "https://a.com/a/1", "https://a.com/b/2", "https://a.com/a/2", "https://a.com/a/3"]
    assert representatives(urls, k=2) == ["https://a.com/b", "https://a.com/a/1", "https://a.com/b/2", "https://a.com/a/2"]


def test_representatives_exclude_static_and_duplicates():
    urls = ["https://a.com/app.js", "https://a.com/x", "https://a.com/x", "https://a.com/logo.png", "https://a.com/y"]
    assert representatives(urls, k=2) == ["https://a.com/x", "https://a.com/y"]


def test_representatives_default_k_is_two_and_k_floor_is_one():
    urls = [f"https://a.com/p/{i}" for i in range(5)]
    assert len(representatives(urls)) == 2
    assert len(representatives(urls, k=0)) == 1


def test_representatives_separate_hosts_and_ports():
    urls = ["https://a.com/p/1", "https://b.com/p/1", "https://a.com:8443/p/1"]
    assert representatives(urls, k=1) == urls


# --------------------------------------------------------------------------- #
# Params / priorité
# --------------------------------------------------------------------------- #


def test_has_params():
    assert has_params("https://a.com/s?q=1")
    assert has_params("https://a.com/s?q")
    assert not has_params("https://a.com/s")
    assert not has_params("https://a.com/s?")


@pytest.mark.parametrize("url", [
    "https://a.com/admin", "https://a.com/Admin/login", "https://a.com/administrator/", "https://a.com/wp-admin/x",
    "https://a.com/api/v1/users", "https://a.com/v2/api", "https://a.com/apis/x", "https://a.com/apiv2/x", "https://a.com/api2/x",
    "https://a.com/upload", "https://a.com/uploads/img", "https://a.com/config.php", "https://a.com/configuration/x",
    "https://a.com/debug", "https://a.com/graphql", "https://a.com/swagger/index.html", "https://a.com/actuator/health",
    "https://a.com/internal/tools", "https://a.com/backup.sql", "https://a.com/backups/", "https://a.com/site_config.json",
])
def test_priority_urls(url):
    assert is_priority(url)


@pytest.mark.parametrize("url", [
    "https://a.com/", "https://a.com/capital-markets", "https://a.com/rapide", "https://a.com/therapie",
    "https://a.com/blog/radmin", "https://a.com/produit/12",
    "https://api.a.com/", "https://a.com/search?q=admin", "https://a.com/apical",
])
def test_not_priority_urls(url):
    # Seuls les mots du CHEMIN comptent : ni l'hôte, ni la requête, ni une sous-chaîne.
    assert not is_priority(url)


def test_suspicious_params():
    assert has_suspicious_param("https://a.com/x?redirect=http://evil")
    assert has_suspicious_param("https://a.com/x?ID=3")
    assert has_suspicious_param("https://a.com/x?q=a")
    assert not has_suspicious_param("https://a.com/x?color=red&size=3")
    assert not has_suspicious_param("https://a.com/x")


# --------------------------------------------------------------------------- #
# gf (mock de which / run_command)
# --------------------------------------------------------------------------- #


class FakeGf:
    """run_command factice : `gf -list` puis `gf <motif>` filtrent stdin_from."""

    def __init__(self, installed, hits):
        self.installed, self.hits, self.commands = installed, hits, []

    def __call__(self, command, label, watch=None, timeout=None, stdout_to=None, silent=True, stdin_from=None):
        self.commands.append((list(command), stdin_from))
        if "-list" in command:
            stdout_to.write_text("\n".join(self.installed) + "\n", encoding="utf-8")
        else:
            received = stdin_from.read_text(encoding="utf-8").split()
            urls = [u for u in self.hits.get(command[1], []) if u in received]
            stdout_to.write_text("".join(u + "\n" for u in urls), encoding="utf-8")
        return 0, 0.0, ""


CANDIDATES = ["https://a.com/p?x=1", "https://a.com/q?color=red", "https://a.com/admin", "https://a.com/plain"]


def candidate_file(tmp_path):
    f = tmp_path / "candidates.txt"
    f.write_text("\n".join(CANDIDATES) + "\n", encoding="utf-8")
    return f


def test_gf_absent_returns_none_and_falls_back_to_param_names(tmp_path, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: None)
    called = []
    monkeypatch.setattr(runner, "run_command", lambda *a, **k: called.append(a))
    f = candidate_file(tmp_path)
    assert gf_matches(f, tmp_path) is None
    picked, method = select_priority(CANDIDATES, f, tmp_path)
    assert called == []                                                    # aucun outil lancé
    assert picked == ["https://a.com/admin"]
    assert "gf absent" in method


def test_gf_absent_suspicious_param_names_used(tmp_path, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: None)
    urls = ["https://a.com/go?redirect=/x", "https://a.com/c?color=red", "https://a.com/admin"]
    f = tmp_path / "c.txt"
    f.write_text("\n".join(urls) + "\n", encoding="utf-8")
    picked, _ = select_priority(urls, f, tmp_path)
    assert picked == ["https://a.com/go?redirect=/x", "https://a.com/admin"]


def test_gf_present_adds_its_matches_and_skips_missing_patterns(tmp_path, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: "/usr/bin/gf" if name == "gf" else None)
    fake = FakeGf(installed=["xss", "sqli", "custom"], hits={"xss": ["https://a.com/q?color=red"], "sqli": ["https://a.com/p?x=1", "https://nope/"]})
    monkeypatch.setattr(runner, "run_command", fake)
    f = candidate_file(tmp_path)

    found = gf_matches(f, tmp_path)
    assert found == {"xss": ["https://a.com/q?color=red"], "sqli": ["https://a.com/p?x=1"]}   # ignore les URLs inconnues
    run_patterns = [c[0][1] for c in fake.commands if "-list" not in c[0]]
    assert run_patterns == ["xss", "sqli"]                      # ssrf/redirect/lfi/rce/idor non installés : sautés
    assert all(stdin == f for c, stdin in fake.commands if "-list" not in c)   # stdin depuis le fichier candidat

    picked, method = select_priority(CANDIDATES, f, tmp_path)
    assert picked == ["https://a.com/p?x=1", "https://a.com/q?color=red", "https://a.com/admin"]
    assert "gf" in method and "absent" not in method
    # Les fichiers temporaires de gf ne traînent pas.
    assert not list(tmp_path.glob(".gf_*"))


def test_gf_present_does_not_use_param_name_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: "/usr/bin/gf")
    monkeypatch.setattr(runner, "run_command", FakeGf(installed=["xss"], hits={}))
    f = candidate_file(tmp_path)
    picked, _ = select_priority(CANDIDATES, f, tmp_path)
    assert picked == ["https://a.com/admin"]         # ?x=1 n'est pas retenu : gf fait foi


def test_gf_empty_listing_tries_every_pattern(tmp_path, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: "/usr/bin/gf")
    fake = FakeGf(installed=[], hits={})
    monkeypatch.setattr(runner, "run_command", fake)
    gf_matches(candidate_file(tmp_path), tmp_path)
    assert [c[0][1] for c in fake.commands if "-list" not in c[0]] == list(signatures.GF_PATTERNS)
