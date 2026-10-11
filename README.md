# 🎯 AutoReconV6.4 - Bug Bounty Recon & Post-Recon Automator

![Bash](https://img.shields.io/badge/Language-Bash-4EAA25?style=for-the-badge&logo=gnu-bash&logoColor=white)
![Security](https://img.shields.io/badge/Category-AppSec_&_BugBounty-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

Framework em Bash para recon agressivo na camada de aplicação (Web): subdomínios, URLs históricas/crawling, segredos em JS, WordPress, parâmetros classificados por vetor (XSS/SQLi/SSRF/LFI/...) e nuclei. Sem port scan — 100% foco em AppSec.

**Novo na v6.4:** o script agora pergunta, de forma interativa, onde salvar o output e quais URLs/domínios estão em escopo. Tudo que não está no escopo, é domínio de ruído (Google, GA/GTM, w3.org, CDNs genéricos, analytics) ou é estático não-JS (css/imagem/font/mídia) é descartado antes das fases pesadas — e o filtro é aplicado de novo em cada etapa seguinte.

---

## 🧠 Fluxo (11 fases)

1. **Subdomínios** — `subfinder` + `crt.sh`, filtrados pelo escopo informado.
2. **DNS Resolve** — `puredns` valida hosts vivos.
3. **Web Probing & Tech** — `httpx` (status/title/tech-detect).
4. **URLs Históricas** — `gau` + `waybackurls`.
5. **Crawling Ativo** — `katana`.
   > Fases 4 e 5 rodam em paralelo; cada fonte é filtrada (escopo + ruído + só-JS) antes do merge.
6. **JS Secrets** — `nuclei` varre `.js` em busca de chaves/tokens expostos.
7. **CMS & WPScan** — detecta WordPress e roda `wpscan` em paralelo.
   > Fases 6 e 7 também rodam em paralelo.
8. **Parâmetros** — extrai URLs com parâmetros, deduplicadas por assinatura (path + nomes).
9. **Classificação de Vetores (GF Patterns)** — XSS, SQLi, NoSQLi, RCE, SSTI, LFI, XXE, SSRF, Redirect, CRLF, LDAP.
10. **Headers Sensíveis** — captura headers HTTP via `httpx`.
11. **Nuclei** — CVEs, misconfigs e exposições (critical/high/medium).

---

## ⚙️ Instalação

Ambiente: Linux (Ubuntu/Debian, Kali, Parrot) ou WSL.

```bash
# Dependências base
sudo apt update -y
sudo apt install -y curl wget jq git wpscan golang massdns

# Adicione ao ~/.bashrc ou ~/.zshrc:
export GOPATH=$HOME/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
source ~/.bashrc

# Ferramentas ProjectDiscovery & comunidade
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/gf@latest
go install github.com/d3mondev/puredns/v2@latest

# Patterns do gf (XSS, SQLi, etc.)
mkdir -p ~/.gf
git clone https://github.com/tomnomnom/gf && cp gf/examples/*.json ~/.gf/
git clone https://github.com/1ndianl33t/Gf-Patterns && cp Gf-Patterns/*.json ~/.gf/
rm -rf gf Gf-Patterns
```

---

## 🚀 Como Usar

```bash
git clone https://github.com/denilsonBCJ/AutoReconV6.git
cd AutoReconV6
chmod +x AutoReconV6.4.sh

./AutoReconV6.4.sh target.com
```

Ao rodar, o script pergunta:
1. **Caminho de saída** — ENTER usa o padrão `target.com/recon_YYYY-MM-DD/`.
2. **Escopo** (um domínio/URL por linha, ENTER vazio encerra) — ENTER direto usa só o domínio alvo.

### Flags opcionais

| Flag | Descrição | Exemplo |
|---|---|---|
| `-H "Header: Valor"` | Header customizado enviado ao **alvo** via `httpx`, `katana`, `nuclei` e `wpscan` (ex: identificação de pesquisa). Não é enviado a `subfinder`/`gau`/`waybackurls`/`puredns`/`crt.sh`, que consultam serviços de terceiros. | `-H "X-HackerOne-Research: faisca"` |
| `-R <n>` | Rate limit (req/s), repassado a `subfinder`, `puredns`, `httpx`, `katana`, `nuclei`, `gau` (como threads) e `wpscan` (como throttle em ms = `1000/R`). | `-R 10` |

```bash
./AutoReconV6.4.sh target.com -H "X-HackerOne-Research: faisca" -R 10
./AutoReconV6.4.sh -h   # ajuda
```

---

## 📂 Estrutura Gerada

```text
<output>/
├── scope.txt         # Escopo informado na execução
├── cms/              # Relatórios WPScan
├── params/           # URLs com parâmetros (deduplicadas)
├── tech/             # Tech-detect, headers, js_secrets.txt
├── urls/             # URLs ativas, histórico, crawl, js_files.txt (já filtradas)
├── vectors/          # xss.txt, sqli.txt, ssrf.txt, lfi.txt, etc.
├── subs_alive.txt    # Subdomínios validados (dentro do escopo)
├── final_urls.txt    # Endpoints web vivos e relevantes
└── nuclei.txt         # Vulnerabilidades encontradas
```

---

## ⚠️ Aviso Legal

Uso **estritamente** para programas de Bug Bounty autorizados (HackerOne, Bugcrowd, Intigriti) ou pentests com permissão formal. Uso indevido é ilegal e de responsabilidade exclusiva do operador.

---
*Desenvolvido por Denilson (WhiteSpark) — Pesquisador de Segurança de Aplicações.*