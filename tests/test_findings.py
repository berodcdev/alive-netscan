"""Achados: regras, severidade e ordenação."""

from __future__ import annotations

import pytest

from alive import findings


def host(ip, **extra):
    h = {"ip": ip, "services": set(), "via": "ping", "mac": None, "random_mac": False}
    h.update(extra)
    return h


class TestServicosArriscados:
    @pytest.mark.parametrize(
        "servico,severidade",
        [("telnet", "alto"), ("adb", "alto"), ("rtsp", "alto"), ("vnc", "alto"),
         ("ftp", "medio"), ("rdp", "medio"), ("dvr", "medio"), ("mqtt", "baixo")],
    )
    def test_severidade(self, servico, severidade):
        achados = findings.collect([host("192.168.0.9", services={servico})])
        assert [f.severity for f in achados] == [severidade]

    def test_inclui_o_nome_quando_existe(self):
        h = host("192.168.0.88", services={"telnet"}, name="cam-garagem")
        assert "192.168.0.88 (cam-garagem)" in findings.collect([h])[0].message

    def test_sem_servico_nenhum(self):
        assert findings.collect([host("192.168.0.9")]) == []


class TestMacDuplicado:
    def test_mesmo_mac_em_dois_ips(self):
        hosts = [host("192.168.0.9", mac="aa:bb:cc:dd:ee:01"),
                 host("192.168.0.10", mac="aa:bb:cc:dd:ee:01")]
        achados = findings.collect(hosts)
        assert len(achados) == 1
        assert achados[0].severity == "medio"
        assert "2 IPs" in achados[0].message

    def test_mac_aleatorio_nao_conta(self):
        """MAC sorteado repetido é coincidência esperada, não spoof."""
        hosts = [host("192.168.0.9", mac="6e:bb:cc:dd:ee:01", random_mac=True),
                 host("192.168.0.10", mac="6e:bb:cc:dd:ee:01", random_mac=True)]
        assert findings.collect(hosts) == []


class TestHostsSoArp:
    def test_confirmado_e_aparelho_furtivo(self):
        h = host("192.168.0.10", via="arp", arp_state="confirmado")
        (achado,) = findings.collect([h])
        assert "firewall ativo ou aparelho furtivo" in achado.message

    def test_stale_e_cache_obsoleto(self):
        h = host("192.168.0.63", via="arp", arp_state="stale")
        (achado,) = findings.collect([h])
        assert "cache ARP obsoleto" in achado.message
        assert "podem já ter saído" in achado.message

    def test_os_dois_casos_viram_achados_separados(self):
        hosts = [host("192.168.0.10", via="arp", arp_state="confirmado"),
                 host("192.168.0.63", via="arp", arp_state="stale"),
                 host("192.168.0.65", via="arp", arp_state="stale")]
        mensagens = [f.message for f in findings.collect(hosts)]
        assert len(mensagens) == 2
        assert any("1 host(s) responderam só a ARP" in m for m in mensagens)
        assert any("2 host(s) vêm só de cache" in m for m in mensagens)

    def test_sem_estado_conta_como_confirmado(self):
        """Snapshot antigo ou macOS não tem estado: não inventamos 'obsoleto'."""
        (achado,) = findings.collect([host("192.168.0.10", via="arp")])
        assert "firewall ativo" in achado.message

    def test_trunca_a_lista_de_ips(self):
        hosts = [host(f"192.168.0.{i}", via="arp") for i in range(10, 20)]
        (achado,) = findings.collect(hosts)
        assert achado.message.count("192.168.0.") == 5
        assert "..." in achado.message


class TestRedirecionamentos:
    def test_port_mapping_e_severidade_alta(self):
        wan = {"port_mappings": [{
            "external_port": "32400", "internal_port": "32400",
            "internal_client": "192.168.0.101", "protocol": "TCP",
            "description": "plex",
        }]}
        (achado,) = findings.collect([], wan)
        assert achado.severity == "alto"
        assert "TCP/32400" in achado.message and "[plex]" in achado.message

    def test_sem_wan(self):
        assert findings.collect([], None) == []


def test_ordenacao_por_severidade():
    hosts = [host("192.168.0.9", services={"mqtt"}),      # baixo
             host("192.168.0.8", services={"telnet"}),    # alto
             host("192.168.0.7", services={"ftp"})]       # medio
    assert [f.severity for f in findings.collect(hosts)] == ["alto", "medio", "baixo"]


def test_toda_severidade_tem_cor():
    for sev in findings.SEVERITY_ORDER:
        assert findings.Finding(sev, None, "x").color


class TestShortNotes:
    def test_marca_servicos_graves(self):
        notas = findings.short_notes(host("192.168.0.9", services={"telnet", "adb"}))
        assert set(notas) == {"telnet aberto!", "adb aberto!"}

    def test_sem_nota(self):
        assert findings.short_notes(host("192.168.0.9", services={"http"})) == []


class TestAcaoRecomendada:
    def test_servico_arriscado_diz_o_que_fazer(self):
        h = host("192.168.0.88", services={"telnet"})
        (achado,) = findings.collect([h])
        assert achado.fix and "192.168.0.88" in achado.fix

    def test_redirecionamento_diz_o_que_fazer(self):
        wan = {"port_mappings": [{"external_port": "80", "internal_port": "80",
                                  "internal_client": "192.168.0.9", "protocol": "TCP"}]}
        (achado,) = findings.collect([], wan)
        assert "painel do roteador" in achado.fix

    def test_achado_informativo_nao_tem_acao(self):
        """Host só em ARP não tem ação óbvia — inventar uma seria ruído."""
        (achado,) = findings.collect([host("192.168.0.9", via="arp")])
        assert achado.fix is None

    def test_toda_acao_cabe_numa_linha(self):
        for _sev, _texto, fix in findings._RISKY_SERVICES.values():
            assert len(fix) <= 80, fix


class TestModoPassivo:
    def test_nao_reporta_descoberta_por_arp(self):
        """Em modo passivo todo host vem do ARP: reportar isso seria mentir."""
        hosts = [host("192.168.0.9", via="arp", arp_state="confirmado"),
                 host("192.168.0.10", via="arp", arp_state="stale")]
        assert findings.collect(hosts, passive=True) == []

    def test_servico_arriscado_continua_valendo(self):
        h = host("192.168.0.88", via="arp", services={"telnet"})
        achados = findings.collect([h], passive=True)
        assert len(achados) == 1 and achados[0].severity == "alto"

    def test_sem_passive_reporta_normalmente(self):
        hosts = [host("192.168.0.9", via="arp", arp_state="confirmado")]
        assert len(findings.collect(hosts)) == 1


class TestMitm:
    """Detecção de MITM ancorada no gateway: ARP spoofing / evil twin."""

    GW = "192.168.0.1"
    MAC_A = "a0:b1:c2:d3:e4:f5"  # MAC de fábrica (OUI registrado)
    MAC_B = "a0:b1:c2:00:00:99"  # outro MAC de fábrica

    def _mitm(self, achados):
        return [f for f in achados if f.ip == self.GW]

    def test_mac_do_gateway_mudou(self):
        hosts = [host(self.GW, mac=self.MAC_B)]
        achados = findings.collect(
            hosts, gateway=self.GW, gateway_mac_prev=self.MAC_A
        )
        (a,) = self._mitm(achados)
        assert a.severity == "alto"
        assert self.MAC_A in a.message and self.MAC_B in a.message
        assert a.fix

    def test_mac_igual_ao_anterior_nao_alarma(self):
        hosts = [host(self.GW, mac=self.MAC_A)]
        achados = findings.collect(
            hosts, gateway=self.GW, gateway_mac_prev=self.MAC_A
        )
        assert self._mitm(achados) == []

    def test_sem_historico_nao_alarma_por_mudanca(self):
        hosts = [host(self.GW, mac=self.MAC_A)]
        achados = findings.collect(hosts, gateway=self.GW, gateway_mac_prev=None)
        assert self._mitm(achados) == []

    def test_gateway_com_mac_localmente_administrado(self):
        hosts = [host(self.GW, mac="6e:00:11:22:33:44", random_mac=True)]
        achados = findings.collect(hosts, gateway=self.GW)
        (a,) = self._mitm(achados)
        assert a.severity == "medio"
        assert "localmente administrado" in a.message

    def test_gateway_com_mac_de_fabrica_nao_alarma(self):
        hosts = [host(self.GW, mac=self.MAC_A)]
        achados = findings.collect(hosts, gateway=self.GW)
        assert self._mitm(achados) == []

    def test_mac_do_gateway_duplicado_e_spoof_alto(self):
        """MAC do gateway respondendo em outro IP: ARP spoofing clássico."""
        hosts = [
            host(self.GW, mac=self.MAC_A),
            host("192.168.0.77", mac=self.MAC_A),
        ]
        achados = findings.collect(hosts, gateway=self.GW)
        alto = [f for f in achados if f.severity == "alto"]
        assert len(alto) == 1
        assert "192.168.0.77" in alto[0].message
        assert "ARP spoofing" in alto[0].message

    def test_mac_duplicado_sem_ser_gateway_continua_medio(self):
        hosts = [
            host("192.168.0.9", mac=self.MAC_A),
            host("192.168.0.10", mac=self.MAC_A),
        ]
        achados = findings.collect(hosts, gateway=self.GW)
        assert [f.severity for f in achados] == ["medio"]

    def test_sem_gateway_nenhuma_regra_mitm_dispara(self):
        hosts = [host(self.GW, mac="6e:00:11:22:33:44", random_mac=True)]
        assert findings.collect(hosts) == []


class TestSnmpPublico:
    def test_community_public_vira_achado(self):
        h = host("192.168.0.20", snmp={"community": "public", "descr": "HP"})
        (a,) = [f for f in findings.collect([h]) if "SNMP" in f.message]
        assert a.severity == "medio"
        assert "public" in a.message and a.fix

    def test_sem_snmp_nao_alarma(self):
        h = host("192.168.0.20", snmp={})
        assert [f for f in findings.collect([h]) if "SNMP" in f.message] == []

    def test_nota_na_coluna(self):
        h = host("192.168.0.20", snmp={"community": "public"})
        assert "snmp público!" in findings.short_notes(h)


class TestCertVencido:
    def test_certificado_vencido_vira_achado(self):
        import time
        h = host("192.168.0.50", tls={"subject_cn": "old.local",
                                       "not_after": time.time() - 86400})
        (a,) = [f for f in findings.collect([h]) if "certificado" in f.message]
        assert a.severity == "baixo"
        assert "old.local" in a.message

    def test_certificado_valido_nao_alarma(self):
        import time
        h = host("192.168.0.50", tls={"subject_cn": "ok.local",
                                      "not_after": time.time() + 86400 * 365})
        assert [f for f in findings.collect([h]) if "certificado" in f.message] == []

    def test_sem_validade_nao_alarma(self):
        h = host("192.168.0.50", tls={"subject_cn": "x", "self_signed": True})
        assert [f for f in findings.collect([h]) if "certificado" in f.message] == []

    def test_nota_cert_vencido(self):
        import time
        h = host("192.168.0.50", tls={"not_after": time.time() - 1})
        assert "cert vencido!" in findings.short_notes(h)


class TestDhcpRogue:
    GW = "192.168.0.1"

    def _srv(self, server, router, source=None):
        return {"server": server, "routers": [router], "dns": [],
                "source": source or server, "offered_ip": "192.168.0.100"}

    def test_gateway_diferente_e_rogue_alto(self):
        rogue = self._srv("192.168.0.66", "192.168.0.66")
        (a,) = [f for f in findings.collect([], gateway=self.GW, dhcp=[rogue])
                if "rogue" in f.message]
        assert a.severity == "alto"
        assert "192.168.0.66" in a.message and self.GW in a.message

    def test_dois_servidores_com_gateway_certo(self):
        a = self._srv(self.GW, self.GW)
        b = self._srv("192.168.0.2", self.GW)
        (f,) = [x for x in findings.collect([], gateway=self.GW, dhcp=[a, b])
                if "servidores DHCP" in x.message]
        assert f.severity == "alto"

    def test_um_servidor_legitimo_nao_alarma(self):
        a = self._srv(self.GW, self.GW)
        assert [f for f in findings.collect([], gateway=self.GW, dhcp=[a])
                if "DHCP" in f.message] == []

    def test_dhcp_none_nao_alarma(self):
        assert [f for f in findings.collect([], gateway=self.GW, dhcp=None)
                if "DHCP" in f.message] == []

    def test_dhcp_vazio_nao_alarma(self):
        assert [f for f in findings.collect([], gateway=self.GW, dhcp=[])
                if "DHCP" in f.message] == []


class TestCredencialPadrao:
    """Alerta de login de fábrica: informa, nunca testa. Só com admin exposto."""

    def _h(self, ip, vendor=None, services=None, device=None, **k):
        from alive import classify
        h = host(ip, vendor=vendor, device=device or classify.UNKNOWN)
        h["services"] = services or set()
        h.update(k)
        return h

    def _cred(self, achados):
        return [f for f in achados if "login" in f.message]

    def test_camera_dahua_com_rtsp(self):
        from alive import classify
        h = self._h("192.168.0.50", vendor="Dahua Technology",
                    services={"rtsp", "http"}, device=classify.CAMERA)
        (a,) = self._cred(findings.collect([h]))
        assert a.severity == "alto"
        assert "admin / admin" in a.message

    def test_roteador_tplink_com_http(self):
        from alive import classify
        h = self._h("192.168.0.1", vendor="TP-Link", services={"http"},
                    device=classify.ROUTER)
        (a,) = self._cred(findings.collect([h]))
        assert a.severity == "medio"

    def test_sem_superficie_de_admin_nao_alarma(self):
        from alive import classify
        h = self._h("192.168.0.51", vendor="Dahua", services=set(),
                    device=classify.CAMERA)
        assert self._cred(findings.collect([h])) == []

    def test_guarda_de_tipo_ignora_celular_huawei(self):
        from alive import classify
        h = self._h("192.168.0.8", vendor="Huawei", services={"http"},
                    device=classify.PHONE)
        assert self._cred(findings.collect([h])) == []

    def test_huawei_ont_como_rede_alarma(self):
        from alive import classify
        h = self._h("192.168.0.1", vendor="Huawei", services={"http"},
                    device=classify.NETDEV)
        assert len(self._cred(findings.collect([h]))) == 1

    def test_casa_por_banner_e_nao_so_fabricante(self):
        from alive import classify
        h = self._h("192.168.0.2", services={"http", "mikrotik"},
                    device=classify.NETDEV, banners={"http_server": "MikroTik RouterOS"})
        (a,) = self._cred(findings.collect([h]))
        assert "em branco" in a.message

    def test_fabricante_sem_perfil_nao_alarma(self):
        from alive import classify
        h = self._h("192.168.0.18", vendor="Apple", services={"ssh"},
                    device=classify.COMPUTER)
        assert self._cred(findings.collect([h])) == []

    def test_nota_senha_padrao(self):
        from alive import classify
        h = self._h("192.168.0.50", vendor="Dahua", services={"http"},
                    device=classify.CAMERA)
        assert "senha padrão?" in findings.short_notes(h)

    def test_um_achado_por_host(self):
        from alive import classify
        h = self._h("192.168.0.50", vendor="Dahua", services={"http", "rtsp"},
                    device=classify.CAMERA)
        assert len(self._cred(findings.collect([h]))) == 1


class TestCameraExposta:
    """Cruzamento redirecionamento-de-porta x tipo: câmera aberta pra internet."""

    def _cam(self, ip="192.168.0.50", **k):
        from alive import classify
        h = host(ip, device=classify.CAMERA)
        h["services"] = {"rtsp", "http"}
        h.update(k)
        return h

    def _wan(self, client, ext="8554", inport="554"):
        return {"port_mappings": [{"protocol": "TCP", "external_port": ext,
                "internal_client": client, "internal_port": inport}]}

    def test_camera_exposta_tem_mensagem_propria(self):
        cam = self._cam()
        (f,) = [x for x in findings.collect([cam], wan=self._wan("192.168.0.50"))
                if "internet" in x.message]
        assert f.severity == "alto"
        assert "câmera" in f.message.lower()
        assert "VPN" in f.fix or "vpn" in f.fix

    def test_camera_por_servico_rtsp_mesmo_sem_tipo(self):
        from alive import classify
        h = host("192.168.0.51", device=classify.UNKNOWN)
        h["services"] = {"rtsp"}
        (f,) = [x for x in findings.collect([h], wan=self._wan("192.168.0.51"))
                if "câmera" in x.message.lower()]
        assert f.severity == "alto"

    def test_host_comum_exposto_mostra_o_tipo(self):
        from alive import classify
        pc = host("192.168.0.30", device=classify.COMPUTER)
        pc["services"] = {"ssh"}
        (f,) = [x for x in findings.collect([pc], wan=self._wan("192.168.0.30", "2222", "22"))
                if "redireciona" in x.message]
        assert "computador" in f.message

    def test_destino_desconhecido_nao_quebra(self):
        wan = self._wan("192.168.0.99")
        (f,) = [x for x in findings.collect([], wan=wan) if "redireciona" in x.message]
        assert f.severity == "alto" and "192.168.0.99" in f.message

    def test_sem_redirecionamento_nenhum_achado_de_exposicao(self):
        cam = self._cam()
        assert [x for x in findings.collect([cam]) if "internet" in x.message] == []

    def test_is_camera_helper(self):
        from alive import classify
        assert findings._is_camera(host("1.1.1.1", device=classify.CAMERA)) is True
        h = host("1.1.1.1", device=classify.UNKNOWN)
        h["services"] = {"dvr"}
        assert findings._is_camera(h) is True
        assert findings._is_camera(host("1.1.1.1", device=classify.COMPUTER)) is False


class TestRtspAutenticacao:
    """DESCRIBE distingue stream aberto de câmera protegida por senha."""

    def _cam(self, rtsp_auth=None):
        from alive import classify
        h = host("192.168.0.50", device=classify.CAMERA)
        h["services"] = {"rtsp"}
        h["banners"] = {"rtsp_auth": rtsp_auth} if rtsp_auth else {}
        return h

    def _rtsp(self, achados):
        return [f for f in achados if "RTSP" in f.message]

    def test_aberto_sem_senha_e_alto(self):
        (a,) = self._rtsp(findings.collect([self._cam("open")]))
        assert a.severity == "alto"
        assert "sem autenticação" in a.message

    def test_protegido_por_senha_nao_e_achado(self):
        assert self._rtsp(findings.collect([self._cam("required")])) == []

    def test_auth_desconhecido_mantem_texto_generico(self):
        (a,) = self._rtsp(findings.collect([self._cam(None)]))
        assert a.severity == "alto"
        assert "aberto" in a.message


class TestOnvifAnonimo:
    def _cam(self, **onvif):
        from alive import classify
        h = host("192.168.0.50", device=classify.CAMERA)
        h["services"] = {"rtsp"}
        h["onvif"] = onvif
        return h

    def test_onvif_anonimo_e_medio(self):
        (a,) = [f for f in findings.collect([self._cam(onvif=True, anon=True)])
                if "ONVIF" in f.message]
        assert a.severity == "medio"

    def test_onvif_com_auth_nao_alarma(self):
        h = self._cam(onvif=True)  # sem anon
        assert [f for f in findings.collect([h]) if "ONVIF" in f.message] == []

    def test_nota_onvif_anonimo(self):
        assert "onvif anônimo!" in findings.short_notes(self._cam(anon=True))


class TestFabricanteBotnet:
    def _cam(self, vendor):
        from alive import classify
        h = host("192.168.0.50", device=classify.CAMERA, vendor=vendor)
        h["services"] = {"rtsp"}
        return h

    def test_fabricante_conhecido_vira_aviso(self):
        (a,) = [f for f in findings.collect([self._cam("Dahua Technology")])
                if "botnet" in f.message]
        assert a.severity == "baixo"

    def test_fabricante_neutro_sem_aviso(self):
        h = self._cam("Axis Communications")
        assert [f for f in findings.collect([h]) if "botnet" in f.message] == []

    def test_so_para_camera(self):
        from alive import classify
        h = host("192.168.0.30", device=classify.COMPUTER, vendor="Hikvision")
        h["services"] = {"ssh"}
        assert [f for f in findings.collect([h]) if "botnet" in f.message] == []


class TestTtlContraTipo:
    """TTL de Windows num tipo confirmado que não roda Windows = incoerência."""

    def _h(self, dev, os_family="Windows", inferred=False, vendor="Dahua"):
        h = host("192.168.0.9", vendor=vendor, device=dev)
        h.update({"inferred": inferred, "os_family": os_family})
        return h

    def _ttl(self, achados):
        return [f for f in achados if "TTL" in f.message]

    def test_camera_confirmada_com_ttl_windows(self):
        from alive import classify
        (a,) = self._ttl(findings.collect([self._h(classify.CAMERA)]))
        assert a.severity == "medio"
        assert "camera" in a.message

    def test_tipo_palpite_nao_alarma(self):
        """MAC aleatório + TTL Windows costuma ser notebook Windows, não spoof."""
        from alive import classify
        h = self._h(classify.PHONE, inferred=True)
        assert self._ttl(findings.collect([h])) == []

    def test_computador_com_ttl_windows_e_normal(self):
        from alive import classify
        assert self._ttl(findings.collect([self._h(classify.COMPUTER)])) == []

    def test_ttl_nao_windows_nao_alarma(self):
        from alive import classify
        h = self._h(classify.CAMERA, os_family="Linux/Apple")
        assert self._ttl(findings.collect([h])) == []

    def test_sem_os_family_nao_alarma(self):
        from alive import classify
        h = self._h(classify.CAMERA, os_family=None)
        assert self._ttl(findings.collect([h])) == []
