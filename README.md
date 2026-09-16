<h1 align="center">alive</h1>

<p align="center"><em>host discovery · network recon — direto do terminal</em></p>

<p align="center">
  <img src="assets/demo.gif" alt="demonstração do alive" width="820">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/plataforma-macOS%20%7C%20Linux-2ea043">
  <img src="https://img.shields.io/badge/python-3.9%2B-2ea043">
  <img src="https://img.shields.io/badge/licença-MIT-2ea043">
</p>

`alive` varre a rede local e mostra, numa tabela limpa, **quem e o quê** está conectado:
IP, MAC, fabricante e o **tipo** provável de cada aparelho — `ROTEADOR`, `REDE`,
`COMPUTADOR`, `CELULAR`, `TV/STREAM`, `ASSISTENTE`, `IMPRESSORA`, `CAMERA`, `SERVIDOR`,
`IOT`, `CONSOLE`, `WEARABLE`.

Funciona em **macOS e Linux** sem exigir root: usa `nmap` quando disponível e, caso
contrário, faz um *ping sweep* paralelo combinado com a tabela ARP. Nome e tipo vêm de
oito sinais independentes — DNS reverso, mDNS/Bonjour (com enumeração profunda de
serviços DNS-SD), NetBIOS, SSDP/UPnP, fingerprint por portas TCP, SNMP (`sysDescr`)
o certificado TLS do aparelho e o anúncio ONVIF das câmeras — mais a base de fabricantes OUI (offline).

Com `--watch`, fica monitorando e avisa **quem entra e quem sai** da rede. E ao final de cada
varredura lista os **achados**: serviço em texto puro exposto, câmera com RTSP aberto, ADB
acessível, MAC duplicado e — via UPnP — os **redirecionamentos de porta ativos no seu
roteador**, ou seja, o que está aberto para a internet. Detecta ainda **servidor DHCP rogue** (sob `sudo`), o vetor de MITM mais silencioso: um DHCP
não autorizado que entrega a si mesmo como gateway. Vigia também o **gateway**, alvo nº 1
de ARP spoofing numa rede interna: avisa quando o MAC do roteador **muda** entre scans, quando
o IP dele responde com um **MAC forjado**, ou quando **outro aparelho responde com o MAC do
gateway** — a assinatura de um ataque man-in-the-middle em andamento.

---

## ⚠️ Uso autorizado — leia antes

> **Use o `alive` SOMENTE em redes que você administra ou tem autorização explícita para
> auditar.** Varrer redes de terceiros sem permissão é invasão e pode ser **crime** na sua
> jurisdição. Esta ferramenta é para diagnóstico da sua própria rede, laboratórios e testes
> autorizados. Você é o único responsável pelo uso que fizer dela.

---

## Instalação

**Via PyPI** (recomendado — `pipx` isola as dependências):

```bash
pipx install alive-netscan     # ou: pip install --user alive-netscan
```

**Arch Linux** (AUR):

```bash
yay -S alive-netscan           # ou paru, ou makepkg em packaging/aur/
```

**Via script** (clona e monta um ambiente isolado, sem tocar no Python do sistema):

```bash
git clone https://github.com/berodcdev/alive-netscan.git
cd alive-netscan
./install.sh
```

O instalador detecta seu sistema (Homebrew, apt, dnf, pacman, zypper), escolhe um Python 3
saudável, cria um **ambiente isolado** (`venv` em `~/.local/share/alive`) com todas as
dependências, expõe o comando `alive` via symlink em `~/.local/bin` (ajustando o `PATH` se
preciso) e oferece instalar o `nmap` (opcional, mas recomendado).

```bash
./install.sh --with-nmap   # instala e já traz o nmap
./install.sh --no-nmap     # instala sem tocar no nmap
./install.sh --uninstall   # remove o alive
```

## Uso

```bash
alive                      # varre a rede WiFi atual
alive --demo               # demonstração com dados fictícios
alive -h                   # ajuda completa (colorida)
alive --fast               # rápido: pula mDNS, fabricante e as sondas
alive -n 192.168.0.0/24    # varre uma subrede específica
alive -i wlan0             # força uma interface
alive --watch              # monitora e avisa quem entra e sai (a cada 30s)
alive --watch 60           # monitorando a cada 60 segundos
alive --passive            # não manda pacote nenhum: só o cache ARP + mDNS
alive --stealth            # furtivo: ordem aleatória, jitter, poucos workers
alive --sort type          # agrupa por tipo, infraestrutura primeiro
alive --sort risk          # host com o achado mais grave primeiro
alive --json > recon.json  # saída em JSON para automação
```

Para automação, pipeline e monitoramento:

```bash
alive -o targets | nmap -iL -   # só os IPs, para alimentar outra ferramenta
alive -o csv > rede.csv         # uma linha por host, para planilha
alive --with-service smb        # só hosts que expõem SMB (combina com -o)
alive --cameras                 # foco em câmeras: exposição de cada uma
alive --watch --json            # NDJSON: uma linha por ciclo, com os eventos
alive --watch --on-event 'notify-send alive "$ALIVE_SUMMARY"'  # IDS caseiro: avisa no desktop
alive --fail-on alto            # sai com código 3 se houver achado grave (cron/CI)
alive -n 10.0.0.0/16 --force    # redes acima de /20 exigem --force
```

> 💡 Veja a saída sem escanear nada: **`alive --demo`** (é o que aparece no GIF acima).

Cada sonda pode ser desligada: `--no-nmap`, `--no-mdns`, `--no-vendor`, `--no-ports`,
`--no-upnp`, `--no-netbios`, `--no-snmp`, `--no-dhcp`, `--no-history`.

**`--passive`** desliga todas de uma vez: nenhum pacote sai daqui para os hosts. Sobram
a tabela ARP que o sistema já mantém e a escuta de mDNS (multicast, o tráfego que a rede
já troca sozinha). Cobre menos, mas não deixa rastro em IDS nem acorda aparelho dormindo.

## Como funciona

| Etapa | O que faz |
|-------|-----------|
| **Rede** | interface, IP, subrede, gateway, SSID, canal/sinal do WiFi e DNS em uso (avisa se a rota padrão sai por VPN) |
| **Scan** | `nmap -sn` (se houver) + ping sweep paralelo, guardando RTT e TTL; **a tabela ARP também é fonte de hosts** — é assim que aparecem os aparelhos que ignoram ping. O estado do vizinho é lido junto: quem veio de cache não revalidado é marcado como `ARP obsoleto`, não como presença confirmada |
| **Nomes** | DNS reverso, mDNS/Bonjour, NetBIOS (Windows/Samba) e `friendlyName` do UPnP |
| **Modelo** | TXT do mDNS (`MacBook Air`, `Chromecast Ultra`, modelo da impressora), `sysDescr` do SNMP, CN do certificado TLS, banner de SSH/HTTP/RTSP e família de SO pelo TTL |
| **Fingerprint** | fabricante por OUI (offline) + ~24 portas TCP (inclui 8443/8554 de câmera) + SNMP `public` + certificado TLS (CN/SAN) que identificam o aparelho |
| **Classificação** | combina modelo, fabricante, serviços, portas, UPnP e hostname — marca `?` quando é palpite |
| **Histórico** | compara com o scan anterior: marca quem é `NOVO`, quem saiu e há quanto tempo cada um é conhecido |
| **Achados** | serviços expostos, MAC duplicado, sinais de ARP spoofing no gateway (MITM), servidor DHCP rogue, SNMP `public` aberto, certificado TLS vencido, aparelho com login de fábrica conhecido, câmera exposta à internet, incoerência de TTL x tipo (spoof) e os redirecionamentos de porta ativos no roteador — cada um com o que fazer a respeito |

Sem `nmap` ou sem `sudo`, o `alive` ainda funciona — apenas pode não ver aparelhos que
ignoram ping. Instalar `nmap` e/ou rodar com `sudo` melhora a cobertura de MACs.

### Por que alguns aparecem como `aleatório` e `CELULAR ?`

Celulares (e Macs) ligam o **endereço Wi-Fi privado** por padrão: sorteiam um MAC
*locally administered* por rede. Não existe fabricante para consultar — a faixa não pertence
a ninguém. Em vez de mostrar um `?` sem explicação, o `alive` rotula esses como `aleatório`
e usa o próprio fato como pista: MAC sorteado, sem serviço nenhum exposto, é quase sempre um
celular — daí o `CELULAR ?`, onde o `?` significa "inferido, não confirmado".

O histórico leva isso em conta: para MAC aleatório a identidade é o IP, senão todo celular
apareceria como `NOVO` em cada scan.

## Requisitos

- Python 3.9+ (o instalador escolhe automaticamente uma versão saudável)
- Deps Python (instaladas no venv): `rich`, `rich-argparse`, `zeroconf`, `mac-vendor-lookup`
- Opcional: `nmap` (melhora a cobertura do scan)

O `alive` fica isolado no próprio ambiente virtual — não polui o Python do sistema. As sondas
de porta, SSDP e NetBIOS usam só a biblioteca padrão. O histórico do `--watch` fica em
`~/.local/state/alive/history.json` (`--no-history` desliga).

## Problemas comuns

**Ele escaneou uma rede estranha (`10.x`, `100.64.x`) em vez da minha WiFi**

Sua rota padrão está saindo por uma VPN/túnel — o `alive` avisa quando detecta isso. Aponte a
interface física:

```bash
alive -i en0      # macOS
alive -i wlan0    # Linux
```

**`ensurepip is not available` / falha ao criar o venv (Debian, Ubuntu, Raspberry Pi OS)**

Nessas distros o módulo `venv` vem sem o `ensurepip`. O instalador tenta resolver sozinho
(instala o pacote correto ou baixa o pip via `get-pip.py`); se ainda falhar, rode:

```bash
sudo apt install -y python3-venv   # ou pythonX.Y-venv, ex.: python3.14-venv
./install.sh
```

**`alive: command not found` depois de instalar**

O comando fica em `~/.local/bin`. Reabra o terminal ou rode:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

## Desenvolvimento

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest          # suíte completa
ruff check .    # lint
```

Todo o parsing da ferramenta (MAC, TTL, tabela ARP, saída do nmap, NBSTAT, XML do
UPnP, nomes e classificação) é função pura e está coberto por testes — é onde os
bugs moram. O CI roda `pytest` em Python 3.9–3.13 no Linux e no macOS, mais
`ruff` e `shellcheck install.sh`.

## Contribuindo

Contribuições são bem-vindas! Abra uma issue ou PR — o CI precisa passar. Ideias
úteis: mais regras de classificação por fabricante/serviço, suporte a IPv6, mais
gerenciadores de pacotes.

O GIF de demonstração é gerado com [VHS](https://github.com/charmbracelet/vhs):
`vhs assets/demo.tape` (usa `alive --demo`, sem expor nenhuma rede real).

## Segurança

O `alive` só fala com aparelhos da própria LAN, e trata tudo que eles dizem como
entrada não confiável: a URL que um aparelho anuncia por SSDP é seguida apenas se
for `http://` do próprio IP que respondeu, sem redirecionamento — senão qualquer
aparelho da rede poderia apontar o `alive` para `file:///etc/passwd` ou para um
host interno arbitrário. Nomes e banners vindos da rede são sempre escapados
antes de ir para a tela.

As sondas ativas se limitam a: um ping por host, uma conexão TCP em ~22 portas que
*identificam* o aparelho, a leitura do banner de quem já estava com a porta aberta,
um GetRequest SNMP só-leitura com a community padrão `public`, a leitura do
certificado que o host apresenta no handshake TLS e um DHCP DISCOVER em broadcast
para detectar servidor DHCP rogue. Não há teste de credencial, força bruta de
community nem exploração — só o `public` universalmente conhecido, e só leitura. O
DISCOVER nunca é seguido de REQUEST, então nenhum lease é fechado. O TLS não é verificado ao ler banner HTTPS, porque aparelhos de LAN usam
certificado autoassinado — nenhum dado é enviado, só lido.

O alerta de **credencial padrão** é só um aviso: o `alive` reconhece o modelo e lembra que ele
sai de fábrica com um login conhecido (informação pública do manual), mas **nunca tenta
autenticar** — não há login, força bruta nem verificação de senha.

## Licença

Distribuído sob a licença **MIT**. Veja [`LICENSE`](LICENSE) para o texto completo.

<p align="center"><sub>feito por <a href="mailto:dev@bernardorodc.com">dev@bernardorodc.com</a></sub></p>
