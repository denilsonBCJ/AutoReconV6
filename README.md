# 🎯 AutoReconV6 - Bug Bounty Recon & Post-Recon Automator

![Bash](https://img.shields.io/badge/Language-Bash-4EAA25?style=for-the-badge&logo=gnu-bash&logoColor=white)
![Security](https://img.shields.io/badge/Category-AppSec_&_BugBounty-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

O **AutoReconV6 (No-PortScan & Deep CMS/JS Edition)** é um framework em Bash voltado para automação agressiva de reconhecimento na camada de aplicação (Web). 

Nesta versão, o ruído de *port scanning* pesado foi removido para focar 100% em **Application Security**: extração de parâmetros vulneráveis, caça a chaves de API/Segredos vazados em arquivos JavaScript e exploração automatizada de instâncias WordPress (CMS). É a ferramenta perfeita para mapear cirurgicamente a superfície de ataque web de um alvo.

**Novidade (v6.1):** suporte a header HTTP customizado (ex: identificação de pesquisa `X-HackerOne-Research`) e a rate limit configurável, repassados automaticamente para as ferramentas da pipeline. Veja a seção [⚙️ Parâmetros Opcionais](#️-parâmetros-opcionais-v61).

---

## 🧠 Fluxo de Execução (As 11 Fases)

O script executa uma pipeline contínua de segurança ofensiva focada em Web:

1. **Enumeração Passiva:** Coleta de subdomínios via `subfinder` e parsing do `crt.sh`.
2. **Resolução DNS Ativa:** Validação super rápida de *live hosts* via `puredns`.
3. **Web Probing & Tech:** Identificação de servidores web ativos e tecnologias com `httpx`.
4. **Coleta Histórica:** Mineração de endpoints antigos e ocultos utilizando `gau` e `waybackurls`.
5. **Crawling Ativo:** Navegação e extração de rotas em tempo real com `katana`.
6. **Análise de JavaScript & Segredos (NOVO):** Isolamento de arquivos `.js` e varredura automatizada com `nuclei` em busca de chaves da AWS, tokens de API e credenciais *hardcoded*.
7. **Detecção de CMS & WPScan (NOVO):** Identificação de alvos rodando WordPress e execução automática de *scanning* passivo em busca de plugins vulneráveis e usuários expostos.
8. **Extração de Parâmetros:** Isolamento inteligente de URLs que contêm parâmetros (`?id=`, `?url=`, etc.).
9. **Classificação de Vetores (GF Patterns):** Categorização das rotas vulneráveis para ataques de `XSS`, `SQLi`, `SSRF`, `LFI`, e `Open Redirect`.
10. **Headers Sensíveis:** Extração e armazenamento de cabeçalhos HTTP que possam vazar informações do servidor.
11. **Scanning de Vulnerabilidades:** Execução do `nuclei` focada em CVEs, exposições e *misconfigs*.

---

## ⚙️ Instalação Passo a Passo

O ambiente ideal para execução é **Linux (Ubuntu/Debian, Kali, Parrot)** ou **WSL no Windows**.

### 1. Pacotes Base do Sistema e WPScan
Abra o seu terminal e instale as dependências essenciais:

```bash
sudo apt update -y
sudo apt install -y curl wget jq git wpscan
```

### 2. Instalação da Linguagem Go (Golang)
```bash
sudo apt install -y golang
```

*Adicione as linhas abaixo ao final do seu arquivo `~/.bashrc` ou `~/.zshrc`:*
```bash
export GOPATH=$HOME/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
```
*Atualize o terminal executando:* `source ~/.bashrc`

### 3. Instalando as Ferramentas do ProjectDiscovery & Comunidade
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/gf@latest
```

### 4. Instalando o PureDNS (Requer Massdns)
```bash
sudo apt install -y massdns
go install github.com/d3mondev/puredns/v2@latest
```

### 5. Configurando o GF e as Patterns
O `gf` precisa das assinaturas (patterns) para classificar XSS, SQLi, etc.

```bash
# Crie o diretório de configuração do gf
mkdir -p ~/.gf

# Clone o repositório oficial e copie os exemplos
git clone https://github.com/tomnomnom/gf
cp gf/examples/*.json ~/.gf/

# Clone as patterns focadas em Bug Bounty
git clone https://github.com/1ndianl33t/Gf-Patterns
cp Gf-Patterns/*.json ~/.gf/

# Remova as pastas clonadas
rm -rf gf Gf-Patterns
```

---

## 🚀 Como Usar

Com todas as dependências instaladas, clone o repositório e execute:

```bash
# Clone o projeto
git clone https://github.com/denilsonBCJ/AutoReconV6.git

# Acesse a pasta
cd AutoReconV6

# Dê permissão de execução
chmod +x AutoReconV6.sh

# Execute apontando para o seu alvo (forma básica)
./AutoReconV6.sh target.com
```

### Com header customizado e/ou rate limit (v6.1)

```bash
# Só com header de identificação de pesquisa
./AutoReconV6.sh target.com -H "X-HackerOne-Research: faisca"

# Só com rate limit (requisições/segundo)
./AutoReconV6.sh target.com -R 10

# Combinando os dois (ordem dos parâmetros não importa)
./AutoReconV6.sh target.com -H "X-HackerOne-Research: faisca" -R 10
```

Se nenhuma das duas flags for passada, o script roda exatamente como antes, usando os valores padrão de cada ferramenta.

---

## ⚙️ Parâmetros Opcionais (v6.1)

| Flag | Descrição | Exemplo |
|---|---|---|
| `-H "Header: Valor"` | Header HTTP customizado enviado nas requisições feitas **contra o alvo**. Útil para se identificar em programas que pedem isso (ex: `X-HackerOne-Research`). | `-H "X-HackerOne-Research: faisca"` |
| `-R <n>` | Limite de requisições por segundo, repassado para as ferramentas da pipeline. Inteiro positivo. | `-R 10` |

**Onde o header (`-H`) é aplicado:** apenas nas ferramentas que fazem requisições diretamente à infraestrutura do alvo — `httpx`, `katana`, `nuclei` e `wpscan` (via `--headers`). Ele **não** é enviado para `subfinder`, `gau`, `waybackurls`, `puredns` ou para a consulta ao `crt.sh`, pois essas requisições vão para serviços de terceiros (Wayback Machine, crt.sh, resolvers DNS, APIs passivas) e não para o alvo em si.

**Onde o rate limit (`-R`) é aplicado:**

| Ferramenta | Flag usada internamente |
|---|---|
| `subfinder` | `-rate-limit` |
| `puredns` | `--rate-limit` |
| `httpx` | `-rate-limit` |
| `katana` | `-rate-limit` |
| `nuclei` | `-rate-limit` |
| `gau` | `--threads` (aproximação, já que o `gau` não tem rate limit real por segundo) |
| `wpscan` | `--throttle` em milissegundos, calculado como `1000 / R` |

Use `-R` menor (ex: `-R 5` ou `-R 10`) em alvos sensíveis ou com WAF agressivo, e omita a flag para deixar cada ferramenta rodar no seu ritmo padrão (geralmente mais rápido).

### Ajuda rápida

```bash
./AutoReconV6.sh -h
```

### Estrutura de Diretórios Gerada

```text
[target.com/recon_YYYY-MM-DD/](https://target.com/recon_YYYY-MM-DD/)
├── cms/             # Relatórios do WPScan e alvos WordPress identificados
├── params/          # URLs com parâmetros extraídos prontos para fuzzing
├── tech/            # Tecnologias web, HTTP status, headers e segredos JS (js_secrets.txt)
├── urls/            # URLs ativas, histórico (Wayback/Gau), crawling e lista de arquivos JS
├── vectors/         # Endpoints separados por vulnerabilidade (xss.txt, sqli.txt, etc.)
├── subs_alive.txt   # Subdomínios validados pelo puredns
├── final_urls.txt   # Endpoints web respondendo (HTTP/HTTPS)
└── nuclei.txt       # Reporte final de vulnerabilidades gerais
```

---

## ⚠️ Aviso Legal e Ética

Este projeto foi construído **estritamente para fins educacionais e uso em programas de Bug Bounty autorizados** (como HackerOne, Bugcrowd, Intigriti) ou testes de invasão com permissão formal. O uso indevido é ilegal e de total responsabilidade do operador.

---
*Desenvolvido com ☕ e focado em resultados por Denilson (WhiteSpark) - Pesquisador de Segurança de Aplicações.*