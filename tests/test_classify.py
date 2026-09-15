"""Matriz de classificação: cada sinal leva ao tipo certo, e o palpite é marcado."""

from __future__ import annotations

import pytest

from alive import classify as tipos


def classificar(**kwargs):
    base = {
        "ip": "192.168.0.50", "mac": None, "vendor": None, "hostname": None,
        "mdns_name": None, "services": None, "gateway": "192.168.0.1",
        "upnp": None, "model": None, "banners": None, "os_family": None,
    }
    base.update(kwargs)
    return tipos.classify(**base)


class TestGateway:
    def test_gateway_e_sempre_roteador(self):
        """Nem OUI de câmera muda isso: quem roteia é o roteador."""
        dev, palpite = classificar(ip="192.168.0.1", vendor="Hikvision")
        assert dev is tipos.ROUTER and palpite is False


class TestModelo:
    @pytest.mark.parametrize(
        "model,esperado",
        [
            ("MacBook Air", tipos.COMPUTER),
            ("iPhone", tipos.PHONE),
            ("Chromecast Ultra", tipos.TV),
            ("Apple TV", tipos.TV),
            ("Echo Dot", tipos.SPEAKER),
            ("Nest Mini", tipos.SPEAKER),
            ("Apple Watch", tipos.WATCH),
            ("HP LaserJet M28w", tipos.PRINTER),
        ],
    )
    def test_modelo_anunciado_e_certeza(self, model, esperado):
        dev, palpite = classificar(model=model)
        assert dev is esperado and palpite is False


class TestServicosDecisivos:
    @pytest.mark.parametrize(
        "servico,esperado",
        [
            ("ios", tipos.PHONE),          # porta 62078: só iPhone/iPad
            ("adb", tipos.PHONE),
            ("ipp", tipos.PRINTER),
            ("jetdirect", tipos.PRINTER),
            ("amzn-alexa", tipos.SPEAKER),
            ("dvr", tipos.CAMERA),
            ("mikrotik", tipos.NETDEV),
            ("plex", tipos.SBC),
        ],
    )
    def test_porta_prova_o_tipo(self, servico, esperado):
        dev, palpite = classificar(services={servico})
        assert dev is esperado and palpite is False

    def test_cast_com_nome_de_audio_vira_assistente(self):
        dev, _ = classificar(services={"cast"}, hostname="nest-audio-sala")
        assert dev is tipos.SPEAKER

    def test_cast_sem_pista_de_audio_vira_tv(self):
        dev, _ = classificar(services={"cast"}, hostname="sala")
        assert dev is tipos.TV

    def test_rtsp_sozinho_e_palpite_de_camera(self):
        """Media server também fala RTSP — sem DVR junto, fica no palpite."""
        dev, palpite = classificar(services={"rtsp"})
        assert dev is tipos.CAMERA and palpite is True

    def test_rtsp_com_dvr_e_certeza(self):
        dev, palpite = classificar(services={"rtsp", "dvr"})
        assert dev is tipos.CAMERA and palpite is False


class TestPalavrasChave:
    @pytest.mark.parametrize(
        "hostname,esperado",
        [
            ("Galaxy-S23", tipos.PHONE),
            ("meu-iphone", tipos.PHONE),
            ("PlayStation-5", tipos.GAME),
            ("xbox-sala", tipos.GAME),
            ("raspberrypi", tipos.SBC),
            ("cam-garagem", tipos.CAMERA),
            ("repetidor-quarto", tipos.NETDEV),
            ("Echo-Cozinha", tipos.SPEAKER),
        ],
    )
    def test_hostname(self, hostname, esperado):
        dev, _ = classificar(hostname=hostname)
        assert dev is esperado


class TestFabricante:
    @pytest.mark.parametrize(
        "vendor,esperado",
        [
            ("Amazon Technologies Inc.", tipos.SPEAKER),
            ("Google LLC", tipos.SPEAKER),
            ("Samsung Electronics Co.,Ltd", tipos.TV),
            ("Raspberry Pi Foundation", tipos.SBC),
            ("Hikvision Digital Technology", tipos.CAMERA),
            ("Espressif Inc.", tipos.IOT),
            ("Nintendo Co., Ltd.", tipos.GAME),
            ("Xiaomi Communications", tipos.PHONE),
            ("Apple, Inc.", tipos.COMPUTER),
            ("Dell Inc.", tipos.COMPUTER),
        ],
    )
    def test_oui(self, vendor, esperado):
        dev, _ = classificar(vendor=vendor)
        assert dev is esperado

    def test_fabricante_de_rede_fora_do_gateway_e_palpite(self):
        """A Intelbras vende de câmera a roteador: sem outro sinal, é palpite."""
        dev, palpite = classificar(vendor="Intelbras")
        assert dev is tipos.NETDEV and palpite is True


class TestBanners:
    @pytest.mark.parametrize(
        "banner,esperado",
        [
            ({"http_server": "GoAhead-Webs"}, tipos.CAMERA),
            ({"http_server": "lighttpd/1.4.45 OpenWrt"}, tipos.NETDEV),
            ({"ssh": "OpenSSH_9.6p1 Debian-3"}, tipos.SBC),
            ({"http_server": "CUPS/2.4"}, tipos.PRINTER),
        ],
    )
    def test_servidor_embarcado(self, banner, esperado):
        dev, _ = classificar(banners=banner)
        assert dev is esperado


class TestUltimosRecursos:
    def test_mac_aleatorio_sem_sinal_e_palpite_de_celular(self):
        dev, palpite = classificar(mac="6e:1a:c4:90:2d:7b")
        assert dev is tipos.PHONE and palpite is True

    def test_ttl_de_windows(self):
        dev, palpite = classificar(mac="00:1a:2b:3c:4d:5e", os_family="Windows")
        assert dev is tipos.COMPUTER and palpite is True

    def test_sem_nenhum_sinal(self):
        dev, palpite = classificar(mac="00:1a:2b:3c:4d:5e")
        assert dev is tipos.UNKNOWN and palpite is False

    def test_smb_indica_computador(self):
        dev, palpite = classificar(mac="00:1a:2b:3c:4d:5e", services={"smb"})
        assert dev is tipos.COMPUTER and palpite is False

    def test_ssh_sozinho_e_palpite(self):
        dev, palpite = classificar(mac="00:1a:2b:3c:4d:5e", services={"ssh"})
        assert dev is tipos.COMPUTER and palpite is True


def test_todo_tipo_tem_rotulo_e_cor():
    todos = [
        tipos.ROUTER, tipos.NETDEV, tipos.COMPUTER, tipos.PHONE, tipos.TV,
        tipos.SPEAKER, tipos.PRINTER, tipos.CAMERA, tipos.SBC, tipos.IOT,
        tipos.GAME, tipos.WATCH, tipos.UNKNOWN,
    ]
    assert all(t.label and t.label.isupper() and t.color for t in todos)
    assert len({t.label for t in todos}) == len(todos)


class TestFabricanteCasaPorPalavra:
    """Regressão: substring de fabricante gerava tipo errado."""

    @pytest.mark.parametrize(
        "vendor,esperado",
        [
            ("Intelbras", tipos.NETDEV),              # não é "intel" + bras
            ("Intelbras S/A", tipos.NETDEV),
            ("Intel Corporate", tipos.COMPUTER),      # esse sim é Intel
        ],
    )
    def test_intelbras_nao_e_intel(self, vendor, esperado):
        dev, _ = classificar(vendor=vendor)
        assert dev is esperado

    def test_sony_interactive_e_console(self):
        dev, _ = classificar(vendor="Sony Interactive Entertainment")
        assert dev is tipos.GAME

    def test_sony_generica_ainda_e_tv(self):
        dev, _ = classificar(vendor="Sony Corporation")
        assert dev is tipos.TV


class TestPalavraChaveCasaPorPalavra:
    """Regressão: substring em hostname/banner gerava tipo errado."""

    def test_switch_de_rede_nao_e_console(self):
        dev, _ = classificar(hostname="switch-sala", mac="00:1a:2b:3c:4d:5e")
        assert dev is not tipos.GAME

    def test_nintendo_ainda_e_console(self):
        dev, _ = classificar(hostname="Nintendo-Switch")
        assert dev is tipos.GAME

    def test_watchdog_no_banner_nao_e_wearable(self):
        dev, _ = classificar(banners={"http_server": "watchdog/1.2"},
                             mac="00:1a:2b:3c:4d:5e")
        assert dev is not tipos.WATCH

    def test_apple_watch_ainda_e_wearable(self):
        dev, _ = classificar(hostname="apple-watch-bernardo")
        assert dev is tipos.WATCH

    def test_netvision_nao_e_tv(self):
        dev, _ = classificar(hostname="netvision", mac="00:1a:2b:3c:4d:5e")
        assert dev is not tipos.TV

    def test_smart_tv_ainda_e_tv(self):
        dev, _ = classificar(hostname="smart-tv-sala")
        assert dev is tipos.TV

    def test_fragmento_com_hifen_continua_valendo(self):
        """'cam-' foi escrito como fragmento de propósito."""
        dev, _ = classificar(hostname="cam-garagem")
        assert dev is tipos.CAMERA
