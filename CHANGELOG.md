# Changelog

Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/);
versionamento [SemVer](https://semver.org/lang/pt-BR/).

## [0.12.0] — 2026-09-15

### Adicionado
- **Câmera exposta à internet** (fase 2 da auditoria de câmeras). O `alive` já
  lia os redirecionamentos de porta ativos no roteador e já sabia quais hosts
  são câmera; agora cruza os dois. Quando um redirecionamento aponta para uma
  câmera/DVR, o achado deixa de ser "porta X aberta" e passa a dizer que a
  imagem pode estar acessível de fora da rede, com a orientação de usar VPN em
  vez de expor a porta. Nenhuma sonda nova, nenhum acesso ao vídeo — só o
  cruzamento de dados que já tínhamos.

### Alterado
- O achado de redirecionamento de porta agora nomeia o tipo do aparelho de
  destino (ex.: `... para 192.168.0.30 (computador):22`), deixando claro o que
  está exposto.

## [0.11.0] — 2026-09-15

### Adicionado
- **Alerta de credencial padrão de fábrica.** Aparelhos cujo modelo/fabricante
  costuma sair de fábrica com login conhecido (Dahua, Hikvision, Intelbras,
  MikroTik, TP-Link, Ubiquiti, ONT de operadora ZTE/Huawei/Sagemcom, entre
  outros) viram achado, com o login padrão citado e a orientação de trocar. É
  **informação pública** (manual do fabricante), **nunca um teste de login**: o
  `alive` não tenta autenticar em nada. Só dispara quando o aparelho tem uma
  superfície de administração de fato exposta (http, telnet, SSH, RTSP...), para
  o alerta ser acionável, e usa guarda de tipo para não confundir a ONT Huawei
  com o celular Huawei. Marca `senha padrão?` na coluna DETALHE.

## [0.10.0] — 2026-09-15

### Adicionado
- **Empacotamento para distribuição.** O `alive` agora é instalável por
  `pipx install alive-netscan` (PyPI) e, no Arch, pelo AUR
  (`packaging/aur/PKGBUILD`) — sem precisar clonar o repositório. O
  `install.sh` continua como terceira opção.
- Workflow `publish.yml`: ao empurrar uma tag `vX.Y.Z`, faz o build, confere que
  a tag bate com a versão do pacote e publica no PyPI via Trusted Publishing
  (OIDC, sem token no repositório).
- `RELEASING.md` documentando o processo de lançamento (PyPI + AUR).

### Alterado
- Metadados do pacote enriquecidos (classifiers de segurança/rede, URLs de
  changelog e issues) para a página do PyPI.

## [0.9.0] — 2026-09-15

### Adicionado
- **Modo furtivo (`--stealth`)**: ordem de alvos aleatória, atraso (jitter)
  sorteado antes de cada pacote e poucos workers em paralelo. Dissolve a rajada
  sequencial de pings e SYNs que denuncia uma varredura a um IDS. Custa tempo, em
  troca de não deixar a assinatura óbvia. Vale para o ping sweep e o fingerprint
  de portas.
- **Saída armável** para encadear o `alive` com outras ferramentas:
  - `-o/--output {table,json,targets,csv}`: `targets` imprime só os IPs, um por
    linha (`alive -o targets | nmap -iL -`); `csv` dá uma linha por host com
    colunas estáveis, para planilha ou pipeline. `--json` continua valendo como
    atalho de `-o json`.
  - `--with-service SVC`: filtra a saída para os hosts que expõem os serviços
    pedidos (ex.: `--with-service smb,http`), combinável com qualquer formato.
  - `--sort risk`: ordena os hosts pelo achado mais grave de cada um, para
    triar primeiro o que mais importa.

## [0.8.0] — 2026-09-15

### Adicionado
- **Detecção de servidor DHCP rogue**, o vetor de MITM mais silencioso de uma
  rede interna: um DHCP não autorizado entrega a si mesmo como gateway/DNS e
  passa a ver todo o tráfego. O `alive` manda um DHCP DISCOVER em broadcast e
  coleta as OFFERs — se responder mais de um servidor, ou um que ofereça um
  gateway diferente do atual, vira achado `alto`. Nunca manda REQUEST: nenhum
  lease é fechado, nada na rede é perturbado. Os servidores vistos saem em
  `dhcp_servers` no `--json`. Requer a porta 68 (privilegiada): roda sob
  sudo/root e é pulado silenciosamente sem privilégio. Desligável com
  `--no-dhcp`; fora de `--passive` e `--fast`.

## [0.7.0] — 2026-09-15

### Adicionado
- **mDNS profundo**: além da lista fixa de serviços, o `alive` agora enumera o
  meta-serviço DNS-SD (`_services._dns-sd._udp.local.`) e navega dinamicamente
  todo tipo de serviço que a rede anuncia, dentro da mesma janela de tempo. É o
  que desenha o mapa completo de serviços expostos por host — TeamViewer,
  OctoPrint, ESPHome, Sonos, SFTP, AFP, câmera Axis e outros que a lista não
  previa. A lista por host sai em `mdns_services` no `--json`. Desligável mantendo
  o comportamento antigo com `deep=False`.
- Novos tipos reconhecidos por serviço mDNS: Sonos/SoundTouch (assistente),
  câmera Axis, ESPHome e OctoPrint e ponte Philips Hue (IoT), Home Assistant
  (servidor), scanner (impressora); e compartilhamento/acesso remoto
  (AFP, SFTP, DAAP, TeamViewer, GameStream) como computador.

### Corrigido
- A enumeração profunda trazia serviços cujo nome de instância é um identificador
  opaco (o Mac anuncia `_asquic` com um UUID). A heurística de "preferir o nome
  mais longo" deixava esse UUID sobrescrever o nome real do aparelho. Nomes
  opacos (UUID, hex longo, sem letras) agora são descartados na escolha do nome.

## [0.6.0] — 2026-09-15

### Adicionado
- **Consulta SNMP** (161/UDP, community `public`) — o default de fábrica de quase
  toda impressora, switch e access point. Um GetRequest só-leitura de `sysDescr`
  e `sysName` traz modelo, firmware e o nome configurado do aparelho, e alimenta
  a classificação (HP -> impressora, Cisco/RouterOS -> rede). Sem brute force de
  community: só o default universalmente conhecido. Desligável com `--no-snmp`;
  fora do `--passive` e do `--fast`. Um host que responde a `public` vira achado
  `medio`: qualquer um na LAN lê a configuração.
- **Captura do certificado TLS** no mesmo handshake que já lê o banner HTTPS.
  Extrai CN do dono, emissor, nomes alternativos (SAN — o hostname interno vaza
  aqui), validade e se é auto-assinado. Parser X.509 escrito sobre um leitor
  ASN.1/DER mínimo, sem dependência nova. O CN e o SAN alimentam a classificação
  (Synology -> servidor); certificado vencido vira achado `baixo`.
- SNMP e certificado saem na tabela (coluna DETALHE, com marca `snmp público!` /
  `cert vencido!`) e completos no `--json`.
- Assinaturas de `sysDescr`/certificado no mapa de classificação: Cisco, Juniper,
  Aruba, FortiGate, UniFi (rede); Kyocera, Lexmark, Brother (impressora);
  Synology, QNAP, TrueNAS (servidor); Axis (câmera).

## [0.5.0] — 2026-09-15

### Adicionado
- Detecção de MITM ancorada no gateway, o alvo nº 1 de ARP spoofing numa rede
  interna:
  - **MAC do gateway mudou** entre dois scans (via histórico): achado `alto`.
    Roteador não troca de MAC ao reiniciar, então isso é troca física de
    aparelho — ou alguém passou a responder pelo IP do gateway (poisoning /
    evil twin). O MAC do gateway agora persiste no histórico por subrede.
  - **MAC do gateway é localmente administrado**: achado `medio`. Placa de
    roteador de verdade tem MAC de fábrica; um MAC forjado no IP do gateway
    sugere impersonação. Roteador em VM (pfSense/OPNsense) é o falso-positivo
    honesto, por isso `medio` e em forma de pergunta.
  - **MAC do gateway respondendo em outro IP**: ARP spoofing clássico, agora
    `alto` em vez do genérico `medio` de MAC duplicado.

## [0.4.0] — 2026-09-15

Auditoria completa da ferramenta: 9 bugs de corretude, 1 de segurança e a
primeira suíte de testes.

### Segurança
- A URL anunciada por um aparelho via SSDP (`LOCATION`) e o `controlURL` do XML
  UPnP iam direto para `urlopen()` sem validação. Um aparelho hostil na LAN podia
  anunciar `file:///etc/passwd` — lido e parseado — ou apontar para um host
  interno arbitrário, usando o `alive` como proxy de varredura. Agora só `http://`
  do próprio IP que respondeu, e sem seguir redirecionamento.
- Nome de host vindo da rede não passava por escape no bloco "sairam". Um
  aparelho anunciando o nome `[/bold]` por mDNS/NetBIOS derrubava o render
  inteiro com `MarkupError` na varredura seguinte.

### Corrigido
- DNS reverso que devolve o próprio IP (ZTE, Huawei, parte dos TP-Link) era
  aceito como nome e repetia o IP na coluna mais larga da tabela.
- Banner HTTP e XML UPnP sem `html.unescape`: o modelo `Z13220` aparecia como
  `&#90;&#49;&#51;&#50;&#50;&#48;`.
- Header HTTP vazio (`Server:`) fazia o casamento atravessar a quebra de linha e
  devolver o valor do header seguinte — o roteador aparecia como
  `Accept-Ranges: bytes`.
- Entradas ARP em estado `STALE` contavam como host vivo. A ferramenta afirmava
  presença que não tinha verificado; agora `FAILED`/`INCOMPLETE` são descartados
  e `STALE` é reportado como cache obsoleto, na tabela e nos achados.
- Sem limite de tamanho de rede: `-n 10.0.0.0/8` materializava 16,7 milhões de
  IPs e passava de 3 GB de RSS antes do primeiro pacote. Agora recusa acima de
  /20, com `--force` para quem quiser mesmo.
- `Intelbras` casava com `intel` e virava COMPUTADOR — a Intelbras vende câmera e
  roteador. Fabricante agora casa por palavra inteira.
- `Sony Interactive Entertainment` (PlayStation) casava com a entrada de TV, que
  vinha antes da de console na lista.
- Um switch de rede chamado `switch-sala` virava CONSOLE, e um banner com
  `watchdog` virava WEARABLE.
- Títulos HTTP sem informação (`302 Found`, `0,1,2`, `Document`) eram promovidos
  a DETALHE.

### Adicionado
- `--passive`: nenhum pacote unicast para os hosts. Sobram a tabela ARP e a
  escuta de mDNS.
- `--fail-on {alto,medio,baixo}`: sai com código 3 quando há achado nesse nível
  ou pior, para cron e CI.
- `--watch --json` agora emite NDJSON (uma linha por ciclo, com os eventos de
  entrada e saída). Antes não emitia nada: o laço de monitoramento nunca
  serializava, o que deixava o modo inútil para automação.
- Cada achado passa a dizer o que fazer a respeito, não só o que há.
- `--sort type` ordena por prioridade de leitura da rede (infraestrutura
  primeiro), não por alfabeto; e o `--demo` passa a respeitar o `--sort`.
- ONT/CPE de operadora (ZTE, Huawei, Sagemcom, Askey, Arris...) são
  reconhecidos como equipamento de rede em vez de `DESCONHECIDO`.
- Suíte de testes (pytest) sobre todo o parsing: MAC, TTL, tabela ARP, saída do
  nmap, NBSTAT, XML UPnP, validação de URL, nomes, fabricantes, histórico,
  achados e matriz de classificação.
- CI: pytest em Python 3.9–3.13 no Linux e no macOS, `ruff`, `shellcheck` e
  verificação de empacotamento.
- `--force` para varrer redes acima de /20.
- Coluna `!` ligando cada host ao seu achado, e severidade visível
  (`ALTO`/`MÉDIO`/`BAIXO`) no bloco de achados.
- Rodapé com hosts vivos, endereços varridos e duração.
- Campo `arp_state` na saída `--json`.

### Alterado
- A 80 colunas o fabricante entra na coluna DETALHE e a coluna `#` sai; nomes
  passam a truncar com reticência em vez de quebrar no meio da palavra.
- Linhas do resumo, achados e legenda quebram com indentação pendurada, e a
  saída não tem mais espaço no fim das linhas.
- Caixa do fabricante normalizada (`zte` -> `ZTE`).
- `requires-python` sobe para 3.9 (3.8 é EOL desde out/2024).
- Metadados de licença na forma SPDX.

## [0.3.1] — 2026-09-15
- Corrigido `KeyError: 'location'` no SSDP quando o roteador responde.

## [0.3.0] — 2026-09-15
- Cobertura por ARP, modelo do aparelho e achados de segurança.

## [0.2.0] — 2026-09-15
- Fingerprint profundo, MAC aleatório, histórico e `--watch`.

## [0.1.0] — 2026-09-15
- Primeira versão: descoberta de hosts na rede (macOS + Linux).
