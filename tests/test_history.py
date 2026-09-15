"""Histórico entre execuções: identidade do host, diff e rótulo de presença."""

from __future__ import annotations

import time

import pytest

from alive import classify, history


def host(ip, mac=None, name=None):
    return {"ip": ip, "mac": mac, "name": name, "device": classify.COMPUTER}


class TestHostKey:
    def test_mac_real_e_a_identidade(self):
        assert history.host_key(host("192.168.0.9", "f0:18:98:2a:1b:cd")) == \
            "mac:f0:18:98:2a:1b:cd"

    def test_mac_aleatorio_cai_para_ip(self):
        """Senão todo celular apareceria como NOVO a cada varredura."""
        assert history.host_key(host("192.168.0.9", "6e:1a:c4:90:2d:7b")) == \
            "ip:192.168.0.9"

    def test_sem_mac(self):
        assert history.host_key(host("192.168.0.9")) == "ip:192.168.0.9"


class TestAgo:
    @pytest.mark.parametrize(
        "segundos,esperado",
        [(30, "30s"), (90, "1min"), (7200, "2h"), (86400 * 3, "3d")],
    )
    def test_formato(self, segundos, esperado):
        d = history.Diff(previous_time=time.time() - segundos)
        assert d.ago == esperado

    def test_sem_scan_anterior(self):
        assert history.Diff().ago is None


class TestSeenLabel:
    def test_primeira_execucao(self):
        assert history.seen_label({}, first_run=True) == "—"

    def test_visto_agora_pela_primeira_vez(self):
        assert history.seen_label({"first_seen": None}) == "1ª vez"

    def test_presenca_alta_vira_sempre(self):
        h = {"first_seen": time.time() - 86400 * 9, "presence": 0.95, "seen_count": 40}
        assert history.seen_label(h) == "sempre"

    def test_presenca_baixa_mostra_desde_quando(self):
        h = {"first_seen": time.time() - 86400 * 2, "presence": 0.2, "seen_count": 3}
        assert history.seen_label(h) == "há 2d"


@pytest.fixture
def estado(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    return tmp_path


class TestCompareESave:
    def test_primeira_rodada_nao_tem_diff(self, estado):
        d = history.compare([host("192.168.0.9", "f0:18:98:2a:1b:01")], "192.168.0.0/24")
        assert d.first_run is True and d.new_keys == set()

    def test_detecta_novo_e_quem_saiu(self, estado):
        antes = [host("192.168.0.9", "f0:18:98:2a:1b:01", "pc-sala")]
        history.compare(antes, "192.168.0.0/24")
        history.save(antes, "192.168.0.0/24")

        depois = [host("192.168.0.10", "f0:18:98:2a:1b:02", "tv-quarto")]
        d = history.compare(depois, "192.168.0.0/24")
        assert d.new_keys == {"mac:f0:18:98:2a:1b:02"}
        assert [g["name"] for g in d.gone] == ["pc-sala"]
        assert d.first_run is False

    def test_host_conhecido_acumula_contagem(self, estado):
        hosts = [host("192.168.0.9", "f0:18:98:2a:1b:01")]
        for _ in range(3):
            history.compare(hosts, "192.168.0.0/24")
            history.save(hosts, "192.168.0.0/24")
        assert hosts[0]["seen_count"] == 3
        assert hosts[0]["first_seen"] is not None

    def test_redes_diferentes_nao_se_misturam(self, estado):
        history.save([host("192.168.0.9", "f0:18:98:2a:1b:01")], "192.168.0.0/24")
        d = history.compare([host("10.0.0.9", "f0:18:98:2a:1b:02")], "10.0.0.0/24")
        assert d.gone == [] and d.first_run is True

    def test_sem_cidr_nao_grava(self, estado):
        history.save([host("192.168.0.9")], None)
        assert history.compare([host("192.168.0.9")], None).first_run is True

    def test_arquivo_corrompido_nao_derruba(self, estado):
        history.state_path().parent.mkdir(parents=True, exist_ok=True)
        history.state_path().write_text("{lixo", encoding="utf-8")
        assert history.compare([host("192.168.0.9")], "192.168.0.0/24").first_run is True

    def test_escrita_e_atomica(self, estado):
        """Grava em .tmp e renomeia: um ctrl-c não deixa histórico pela metade."""
        history.save([host("192.168.0.9", "f0:18:98:2a:1b:01")], "192.168.0.0/24")
        assert history.state_path().exists()
        assert not history.state_path().with_suffix(".tmp").exists()
