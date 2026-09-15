"""Parsers do scanner: MAC, TTL, saída do nmap e tabela ARP."""

from __future__ import annotations

import ipaddress

import pytest

from alive import scanner


class TestNormalizeMac:
    @pytest.mark.parametrize(
        "raw,esperado",
        [
            ("AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"),
            ("aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff"),
            ("a:b:c:d:e:f", "0a:0b:0c:0d:0e:0f"),
            ("0:1a:2B:3c:4d:5e", "00:1a:2b:3c:4d:5e"),
        ],
    )
    def test_normaliza(self, raw, esperado):
        assert scanner.normalize_mac(raw) == esperado

    @pytest.mark.parametrize(
        "raw",
        [
            None,
            "",
            "aa:bb:cc",                 # incompleto
            "00:00:00:00:00:00",        # endereço nulo
            "ff:ff:ff:ff:ff:ff",        # broadcast
            "(incomplete)",             # o que o `arp -a` do macOS imprime
        ],
    )
    def test_rejeita(self, raw):
        assert scanner.normalize_mac(raw) is None


class TestIsRandomMac:
    @pytest.mark.parametrize("mac", ["ae:d5:ca:bf:c5:d4", "6e:1a:c4:90:2d:7b",
                                     "32:20:8f:ba:eb:8b", "42:50:25:c9:25:96"])
    def test_locally_administered(self, mac):
        """Segundo dígito hex em {2,6,a,e}: MAC sorteado pelo aparelho."""
        assert scanner.is_random_mac(mac) is True

    @pytest.mark.parametrize("mac", ["f0:18:98:2a:1b:cd", "48:96:d9:55:e6:8c",
                                     "dc:a6:32:11:88:f0"])
    def test_oui_real(self, mac):
        assert scanner.is_random_mac(mac) is False

    def test_multicast_nao_conta(self):
        """Bit 0 ligado é multicast, não endereço de aparelho."""
        assert scanner.is_random_mac("03:00:00:00:00:01") is False

    def test_sem_mac(self):
        assert scanner.is_random_mac(None) is False


class TestOsFamilyFromTtl:
    @pytest.mark.parametrize(
        "ttl,esperado",
        [
            (255, "rede/embarcado"),
            (254, "rede/embarcado"),
            (128, "Windows"),
            (127, "Windows"),
            (64, "Linux/Apple"),
            (63, "Linux/Apple"),
            (30, None),
            (0, None),
            (None, None),
        ],
    )
    def test_familia(self, ttl, esperado):
        assert scanner.os_family_from_ttl(ttl) == esperado


IP_NEIGH = """\
192.168.0.1 dev wlan0 lladdr 48:96:d9:55:e6:8c REACHABLE
192.168.0.4 dev wlan0 lladdr 38:16:5a:47:d3:10 STALE
192.168.0.7 dev wlan0  FAILED
192.168.0.9 dev wlan0 lladdr 00:00:00:00:00:00 STALE
192.168.0.11 dev wlan0 lladdr aa:bb:cc:dd:ee:02 DELAY
192.168.0.12 dev wlan0 lladdr aa:bb:cc:dd:ee:03 router REACHABLE
192.168.0.13 dev wlan0 lladdr aa:bb:cc:dd:ee:04 INCOMPLETE
fe80::1 dev wlan0 lladdr 48:96:d9:55:e6:8c router REACHABLE
"""

ARP_A = """\
router (192.168.0.1) at 48:96:d9:55:e6:8c on en0 ifscope [ethernet]
? (192.168.0.5) at (incomplete) on en0 [ethernet]
? (192.168.0.9) at 38:16:5a:47:d3:10 on en0 ifscope [ethernet]
"""


@pytest.fixture
def linux_neigh(monkeypatch):
    monkeypatch.setattr(scanner, "IS_MAC", False)
    monkeypatch.setattr(scanner.shutil, "which", lambda _: "/usr/bin/ip")
    monkeypatch.setattr(
        scanner, "_run",
        lambda cmd, timeout=30.0: IP_NEIGH if cmd[:2] == ["ip", "neigh"] else "",
    )


@pytest.fixture
def mac_arp(monkeypatch):
    monkeypatch.setattr(scanner, "IS_MAC", True)
    monkeypatch.setattr(scanner, "_run", lambda cmd, timeout=30.0: ARP_A)


class TestReadArpEntries:
    def test_estado_do_vizinho(self, linux_neigh):
        entradas = scanner.read_arp_entries()
        assert entradas["192.168.0.1"]["state"] == "confirmado"
        assert entradas["192.168.0.4"]["state"] == "stale"
        assert entradas["192.168.0.11"]["state"] == "confirmado"

    def test_flag_antes_do_estado(self, linux_neigh):
        """'router REACHABLE': a flag não pode ser confundida com o estado."""
        assert scanner.read_arp_entries()["192.168.0.12"]["state"] == "confirmado"

    @pytest.mark.parametrize("ip", ["192.168.0.7", "192.168.0.13"])
    def test_failed_e_incomplete_fora(self, linux_neigh, ip):
        """Vizinho que o kernel não resolveu não é host vivo."""
        assert ip not in scanner.read_arp_entries()

    def test_mac_nulo_fora(self, linux_neigh):
        assert "192.168.0.9" not in scanner.read_arp_entries()

    def test_ignora_ipv6(self, linux_neigh):
        assert all(":" not in ip for ip in scanner.read_arp_entries())

    def test_fallback_arp_a(self, mac_arp):
        """O `arp -a` não expõe estado: tudo vira confirmado."""
        entradas = scanner.read_arp_entries()
        assert set(entradas) == {"192.168.0.1", "192.168.0.9"}
        assert all(e["state"] == "confirmado" for e in entradas.values())

    def test_read_arp_table_so_macs(self, linux_neigh):
        assert scanner.read_arp_table()["192.168.0.1"] == "48:96:d9:55:e6:8c"


NMAP_OUT = """\
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.0.1
Host is up (0.0021s latency).
MAC Address: 48:96:D9:55:E6:8C (Zte)
Nmap scan report for 192.168.0.61
Host is up.
Nmap done: 256 IP addresses (2 hosts up) scanned in 2.15 seconds
"""


def test_nmap_scan(monkeypatch):
    monkeypatch.setattr(scanner, "_run", lambda cmd, timeout=30.0: NMAP_OUT)
    vivos, macs = scanner.nmap_scan("192.168.0.0/24")
    assert vivos == {"192.168.0.1", "192.168.0.61"}
    assert macs == {"192.168.0.1": "48:96:d9:55:e6:8c"}


def test_nmap_scan_saida_vazia(monkeypatch):
    """nmap ausente ou com erro devolve string vazia — não pode explodir."""
    monkeypatch.setattr(scanner, "_run", lambda cmd, timeout=30.0: "")
    assert scanner.nmap_scan("192.168.0.0/24") == (set(), {})


def test_scan_marca_estado_arp(monkeypatch, linux_neigh):
    """Um host que só aparece no ARP carrega o estado até o resultado final."""
    monkeypatch.setattr(scanner, "has_nmap", lambda: False)
    monkeypatch.setattr(scanner, "ping_sweep", lambda *a, **k: {})
    hosts = {h["ip"]: h for h in scanner.scan(ipaddress.ip_network("192.168.0.0/24"))}
    assert hosts["192.168.0.4"]["via"] == "arp"
    assert hosts["192.168.0.4"]["arp_state"] == "stale"
    assert hosts["192.168.0.1"]["arp_state"] == "confirmado"
