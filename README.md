<h1 align="center">alive</h1>

<p align="center"><em>host discovery · network recon — direto do terminal</em></p>

<p align="center">
  <img src="assets/demo.gif" alt="demonstração do alive" width="820">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/plataforma-macOS%20%7C%20Linux-2ea043">
  <img src="https://img.shields.io/badge/python-3.8%2B-2ea043">
  <img src="https://img.shields.io/badge/licença-MIT-2ea043">
</p>

`alive` varre a rede local e mostra, numa tabela limpa, **quem e o quê** está conectado:
IP, MAC, fabricante e o **tipo** provável de cada aparelho — `ROTEADOR`, `COMPUTADOR`,
`CELULAR`, `TV/STREAM`, `ASSISTENTE`, `IMPRESSORA`, `SERVIDOR`, `IOT`, `CONSOLE`.

Funciona em **macOS e Linux** sem exigir root: usa `nmap` quando disponível e, caso
contrário, faz um *ping sweep* paralelo combinado com a tabela ARP. Nomes e tipos vêm de
DNS reverso, mDNS/Bonjour (`zeroconf`) e da base de fabricantes OUI (offline).

---

## ⚠️ Uso autorizado — leia antes

> **Use o `alive` SOMENTE em redes que você administra ou tem autorização explícita para
> auditar.** Varrer redes de terceiros sem permissão é invasão e pode ser **crime** na sua
> jurisdição. Esta ferramenta é para diagnóstico da sua própria rede, laboratórios e testes
> autorizados. Você é o único responsável pelo uso que fizer dela.

---

## Instalação

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
alive --fast               # rápido: só ping sweep + ARP
alive -n 192.168.0.0/24    # varre uma subrede específica
alive -i wlan0             # força uma interface
alive --sort type          # agrupa por tipo de dispositivo
alive --json > recon.json  # saída em JSON para automação
```

> 💡 Veja a saída sem escanear nada: **`alive --demo`** (é o que aparece no GIF acima).

## Como funciona

| Etapa | O que faz |
|-------|-----------|
| **Rede** | detecta interface, IP, subrede (CIDR), gateway e SSID por SO |
| **Scan** | `nmap -sn` (se houver) + ping sweep paralelo; MACs via tabela ARP |
| **Enriquecimento** | DNS reverso, mDNS/Bonjour, fabricante por OUI (offline) |
| **Classificação** | heurística combinando fabricante + serviços mDNS + hostname |

Sem `nmap` ou sem `sudo`, o `alive` ainda funciona — apenas pode não ver aparelhos que
ignoram ping. Instalar `nmap` e/ou rodar com `sudo` melhora a cobertura de MACs.

## Requisitos

- Python 3.8+ (o instalador escolhe automaticamente uma versão saudável)
- Deps Python (instaladas no venv): `rich`, `rich-argparse`, `zeroconf`, `mac-vendor-lookup`
- Opcional: `nmap` (melhora a cobertura do scan)

O `alive` fica isolado no próprio ambiente virtual — não polui o Python do sistema.

## Contribuindo

Contribuições são bem-vindas! Abra uma issue ou PR. Ideias úteis: mais regras de
classificação por fabricante/serviço, suporte a IPv6, mais gerenciadores de pacotes.

O GIF de demonstração é gerado com [VHS](https://github.com/charmbracelet/vhs):
`vhs assets/demo.tape` (usa `alive --demo`, sem expor nenhuma rede real).

## Licença

Distribuído sob a licença **MIT**. Veja [`LICENSE`](LICENSE) para o texto completo.

<p align="center"><sub>feito por <a href="mailto:dev@bernardorodc.com">dev@bernardorodc.com</a></sub></p>
