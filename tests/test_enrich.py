"""Enriquecimento: modelo do mDNS e DNS reverso."""

from __future__ import annotations

import socket

import pytest

from alive import enrich


class TestHumanizeModel:
    @pytest.mark.parametrize(
        "raw,esperado",
        [
            ("MacBookAir10,1", "MacBook Air"),
            ("MacBookPro18,3", "MacBook Pro"),
            ("Macmini9,1", "Mac mini"),
            ("iMac21,1", "iMac"),
            ("iPhone14,5", "iPhone"),
            ("iPad13,1", "iPad"),
            ("Watch6,1", "Apple Watch"),
            ("AppleTV6,2", "Apple TV"),
            ("AudioAccessory5,1", "HomePod"),
        ],
    )
    def test_codigo_apple(self, raw, esperado):
        assert enrich.humanize_model(raw) == esperado

    @pytest.mark.parametrize(
        "raw,esperado",
        [
            ("Chromecast Ultra", "Chromecast Ultra"),
            ("HP LaserJet M28w", "HP LaserJet M28w"),
            ("(Echo Dot)", "Echo Dot"),
        ],
    )
    def test_modelo_ja_legivel(self, raw, esperado):
        assert enrich.humanize_model(raw) == esperado

    def test_prefixo_sem_numero_nao_casa(self):
        """'MacDonalds' não é um Mac — o prefixo só vale seguido de dígito."""
        assert enrich.humanize_model("MacDonalds") == "MacDonalds"

    def test_vazio(self):
        assert enrich.humanize_model(None) is None


class TestExtractModel:
    def test_prefere_a_primeira_chave_disponivel(self):
        assert enrich._extract_model({"md": "Nest Mini"}) == "Nest Mini"

    def test_chave_de_impressora(self):
        assert enrich._extract_model({"ty": "HP DeskJet 2700"}) == "HP DeskJet 2700"

    def test_descarta_generico(self):
        assert enrich._extract_model({"model": "unknown"}) is None

    def test_sem_chave_conhecida(self):
        assert enrich._extract_model({"xyz": "abc"}) is None


class TestReverseDns:
    def test_nome_valido(self, monkeypatch):
        monkeypatch.setattr(socket, "gethostbyaddr",
                            lambda ip: ("raspberrypi.local", [], [ip]))
        assert enrich._reverse_dns("192.168.0.101") == "raspberrypi.local"

    def test_ptr_igual_ao_ip_nao_e_nome(self, monkeypatch):
        """Roteadores ZTE/Huawei devolvem o próprio IP como PTR."""
        monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: (ip, [], [ip]))
        assert enrich._reverse_dns("192.168.0.61") is None

    def test_ptr_com_ponto_final(self, monkeypatch):
        monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: (ip + ".", [], [ip]))
        assert enrich._reverse_dns("192.168.0.61") is None

    def test_sem_ptr(self, monkeypatch):
        def falha(ip):
            raise socket.herror(1, "Unknown host")
        monkeypatch.setattr(socket, "gethostbyaddr", falha)
        assert enrich._reverse_dns("192.168.0.61") is None


def test_resolve_hostnames_lista_vazia():
    assert enrich.resolve_hostnames([]) == {}


def test_lookup_vendors_lista_vazia():
    assert enrich.lookup_vendors([]) == {}
