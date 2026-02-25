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