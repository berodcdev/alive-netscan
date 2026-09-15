"""Descoberta da rede local: rota, máscara, canal WiFi e DNS."""

from __future__ import annotations

import pytest

from alive import net


class TestChannelFromFreq:
    @pytest.mark.parametrize(
        "freq,canal",
        [
            (2412, 1), (2437, 6), (2462, 11), (2484, 14),   # 2.4 GHz
            (5180, 36), (5600, 120), (5825, 165),           # 5 GHz
            (5955, 1), (6175, 45),                          # 6 GHz
        ],
    )
    def test_converte(self, freq, canal):
        assert net.channel_from_freq(freq) == canal

    @pytest.mark.parametrize("freq", [None, 0, 900, 9999])
    def test_fora_das_faixas(self, freq):
        assert net.channel_from_freq(freq) is None


class TestIsVirtualInterface:
    @pytest.mark.parametrize(
        "iface", ["utun3", "tun0", "wg0", "tailscale0", "docker0", "br-abc123", "virbr0"]
    )
    def test_virtual(self, iface):
        assert net.is_virtual_interface(iface) is True

    @pytest.mark.parametrize("iface", ["en0", "wlan0", "wlp0s20f0u5", "eth0", None])
    def test_fisica(self, iface):
        assert net.is_virtual_interface(iface) is False


class TestLinuxDefaultRoute:
    def test_ip_route(self, monkeypatch):
        saida = "default via 192.168.0.1 dev wlan0 proto dhcp src 192.168.0.61 metric 600\n"
        monkeypatch.setattr(net.shutil, "which", lambda _: "/usr/bin/ip")
        monkeypatch.setattr(net, "_run", lambda cmd, timeout=4.0: saida)
        assert net._linux_default_route() == ("wlan0", "192.168.0.1")

    def test_sem_rota_padrao(self, monkeypatch):
        monkeypatch.setattr(net.shutil, "which", lambda _: None)
        monkeypatch.setattr(net, "_run", lambda cmd, timeout=4.0: "")
        assert net._linux_default_route() == (None, None)


class TestNetmask:
    def test_linux_prefixo(self, monkeypatch):
        saida = "3: wlan0    inet 192.168.0.61/24 brd 192.168.0.255 scope global\n"
        monkeypatch.setattr(net.shutil, "which", lambda _: "/usr/bin/ip")
        monkeypatch.setattr(net, "_run", lambda cmd, timeout=4.0: saida)
        assert net._linux_netmask("wlan0") == "24"

    def test_mac_hexmask(self, monkeypatch):
        saida = "\tinet 192.168.0.42 netmask 0xffffff00 broadcast 192.168.0.255\n"
        monkeypatch.setattr(net, "_run", lambda cmd, timeout=4.0: saida)
        assert net._mac_netmask("en0") == "255.255.255.0"


class TestGetNetworkForInterface:
    def test_usa_a_mascara_da_interface(self, monkeypatch):
        monkeypatch.setattr(net, "IS_MAC", False)
        monkeypatch.setattr(net, "_linux_netmask", lambda iface: "16")
        rede = net.get_network_for_interface("wlan0", "192.168.0.61")
        assert str(rede) == "192.168.0.0/16"

    def test_fallback_24(self, monkeypatch):
        """Sem máscara legível, /24 é o palpite razoável numa LAN doméstica."""
        monkeypatch.setattr(net, "IS_MAC", False)
        monkeypatch.setattr(net, "_linux_netmask", lambda iface: None)
        rede = net.get_network_for_interface("wlan0", "192.168.0.61")
        assert str(rede) == "192.168.0.0/24"

    def test_sem_ip(self, monkeypatch):
        monkeypatch.setattr(net, "_linux_netmask", lambda iface: None)
        assert net.get_network_for_interface("wlan0", None) is None


def test_get_dns_servers(monkeypatch, tmp_path):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text(
        "# comentário\nnameserver 192.168.0.1\nnameserver 1.1.1.1\n"
        "nameserver 192.168.0.1\nnameserver 8.8.8.8\nnameserver 9.9.9.9\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(net, "IS_MAC", False)
    real_open = open
    monkeypatch.setattr(
        "builtins.open",
        lambda p, *a, **k: real_open(resolv if p == "/etc/resolv.conf" else p, *a, **k),
    )
    # Sem duplicatas e no máximo três.
    assert net.get_dns_servers() == ["192.168.0.1", "1.1.1.1", "8.8.8.8"]


def test_netinfo_cidr():
    info = net.NetInfo(interface="wlan0", ip="192.168.0.61", network=None,
                       gateway=None, ssid=None)
    assert info.cidr is None
    import ipaddress
    info.network = ipaddress.ip_network("192.168.0.0/24")
    assert info.cidr == "192.168.0.0/24"
