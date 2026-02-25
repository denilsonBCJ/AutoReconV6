# 🎯 AutoReconV6 - Bug Bounty Recon & Post-Recon Automator

![Bash](https://img.shields.io/badge/Language-Bash-4EAA25?style=for-the-badge&logo=gnu-bash&logoColor=white)
![Security](https://img.shields.io/badge/Category-AppSec_&_BugBounty-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

O **AutoReconV6 (No-PortScan & Deep CMS/JS Edition)** é um framework em Bash voltado para automação agressiva de reconhecimento na camada de aplicação (Web). 

Nesta versão, o ruído de *port scanning* pesado foi removido para focar 100% em **Application Security**: extração de parâmetros vulneráveis, caça a chaves de API/Segredos vazados em arquivos JavaScript e exploração automatizada de instâncias WordPress (CMS). É a ferramenta perfeita para mapear cirurgicamente a superfície de ataque web de um alvo.

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
go install -v [github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest](https://github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)
go install -v [github.com/projectdiscovery/httpx/cmd/httpx@latest](https://github.com/projectdiscovery/httpx/cmd/httpx@latest)
go install -v [github.com/projectdiscovery/katana/cmd/katana@latest](https://github.com/projectdiscovery/katana/cmd/katana@latest)
go install -v [github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest](https://github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest)
go install -v [github.com/tomnomnom/waybackurls@latest](https://github.com/tomnomnom/waybackurls@latest)
go install -v [github.com/lc/gau/v2/cmd/gau@latest](https://github.com/lc/gau/v2/cmd/gau@latest)
go install -v [github.com/tomnomnom/anew@latest](https://github.com/tomnomnom/anew@latest)
go install -v [github.com/tomnomnom/gf@latest](https://github.com/tomnomnom/gf@latest)
```

### 4. Instalando o PureDNS (Requer Massdns)
```bash
sudo apt install -y massdns
go install [github.com/d3mondev/puredns/v2@latest](https://github.com/d3mondev/puredns/v2@latest)
```

### 5. Configurando o GF e as Patterns
O `gf` precisa das assinaturas (patterns) para classificar XSS, SQLi, etc.

```bash
# Crie o diretório de configuração do gf
mkdir -p ~/.gf

# Clone o repositório oficial e copie os exemplos
git clone [https://github.com/tomnomnom/gf](https://github.com/tomnomnom/gf)
cp gf/examples/*.json ~/.gf/

# Clone as patterns focadas em Bug Bounty
git clone [https://github.com/1ndianl33t/Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns)
cp Gf-Patterns/*.json ~/.gf/

# Remova as pastas clonadas
rm -rf gf Gf-Patterns
```

---

## 🚀 Como Usar

Com todas as dependências instaladas, clone o repositório e execute:

```bash
# Clone o projeto
git clone [https://github.com/denilsonBCJ/AutoReconV5-.git](https://github.com/denilsonBCJ/AutoReconV5-.git)

# Acesse a pasta
cd AutoReconV5-

# Dê permissão de execução
chmod +x AutoReconV6.sh

# Execute apontando para o seu alvo
./AutoReconV6.sh target.com
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