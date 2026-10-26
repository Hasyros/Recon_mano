"""Garde-fou commun : aucun test ne doit jamais toucher le réseau (crt.sh, cibles…).

Tout accès réseau Python lève une erreur claire. Les tests qui ont besoin d'un
« faux » crt.sh remplacent `urllib.request.urlopen` eux-mêmes (voir `fake_urlopen`).
"""

from __future__ import annotations

import socket
import urllib.request

import pytest


class NetworkBlocked(AssertionError):
    pass


def _blocked(*args, **kwargs):
    raise NetworkBlocked("accès réseau interdit dans les tests (mocker urllib.request.urlopen)")


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket.socket, "connect", _blocked)
