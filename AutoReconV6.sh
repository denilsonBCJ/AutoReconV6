#!/bin/bash

# ==========================================
#  AUTOMAÇÃO RECON + PÓS-RECON (BUG BOUNTY)
#  Versão: 6.1 (No-PortScan & Deep CMS/JS Edition)
#  + Suporte a header customizado (-H) e rate limit (-R)
# ==========================================

# ===== CORES =====
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RESET='\033[0m'

print_banner() {
    echo -e "\n${BLUE}========================================${RESET}"
    echo -e "${YELLOW} ➤ $1 ${RESET}"
    echo -e "${BLUE}========================================${RESET}"
}

show_usage() {
    echo "Uso: $0 <alvo.com> [-H \"Header: Valor\"] [-R requisicoes_por_segundo]"
    echo ""
    echo "  <alvo.com>                 Domínio alvo (obrigatório)"
    echo "  -H \"Header: Valor\"         Header customizado enviado nas requisições"
    echo "                              contra o alvo (ex: -H \"X-HackerOne-Research: faisca\")"
    echo "                              Aplicado em: httpx, katana, nuclei e wpscan."
    echo "  -R <n>                     Limite de requisições/segundo (rate limit) passado"
    echo "                              para as ferramentas que suportam o parâmetro"
    echo "                              (subfinder, puredns, httpx, katana, nuclei, gau, wpscan)."
    echo ""
    echo "Exemplos:"
    echo "  $0 alvo.com"
    echo "  $0 alvo.com -H \"X-HackerOne-Research: faisca\""
    echo "  $0 alvo.com -R 10"
    echo "  $0 alvo.com -H \"X-HackerOne-Research: faisca\" -R 10"
}

# ===== CHECK TOOLS =====
check_tools() {
    REQUIRED_TOOLS=(
        subfinder puredns httpx katana nuclei jq
        gau waybackurls gf anew wpscan
    )
    for tool in "${REQUIRED_TOOLS[@]}"; do
        command -v $tool &>/dev/null || {
            echo -e "${RED}[X] Ferramenta ausente: $tool${RESET}"
            exit 1
        }
    done
}

# ===== PARSE DE ARGUMENTOS =====
TARGET=""
CUSTOM_HEADER=""
MAX_RPS=""

if [ -z "$1" ]; then
    show_usage
    exit 1
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        -H)
            if [ -z "$2" ]; then
                echo -e "${RED}[X] -H requer um valor, ex: -H \"X-HackerOne-Research: faisca\"${RESET}"
                exit 1
            fi
            CUSTOM_HEADER="$2"
            shift 2
            ;;
        -R)
            if [ -z "$2" ]; then
                echo -e "${RED}[X] -R requer um número, ex: -R 10${RESET}"
                exit 1
            fi
            if ! [[ "$2" =~ ^[0-9]+$ ]] || [ "$2" -le 0 ]; then
                echo -e "${RED}[X] -R precisa ser um inteiro positivo (requisições/segundo).${RESET}"
                exit 1
            fi
            MAX_RPS="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        -*)
            echo -e "${RED}[X] Opção desconhecida: $1${RESET}"
            show_usage
            exit 1
            ;;
        *)
            if [ -z "$TARGET" ]; then
                TARGET="$1"
            else
                echo -e "${RED}[X] Argumento inesperado: $1${RESET}"
                show_usage
                exit 1
            fi
            shift
            ;;
    esac
done

if [ -z "$TARGET" ]; then
    echo -e "${RED}[X] Nenhum domínio alvo informado.${RESET}"
    show_usage
    exit 1
fi

check_tools

DOMAIN=$(echo "$TARGET" | sed 's|https\?://||;s|/$||')
DATE=$(date +%F)
WORK="$DOMAIN/recon_$DATE"
mkdir -p "$WORK"/{urls,params,vectors,tech,cms}

RESOLVERS="$WORK/resolvers.txt"
[ ! -f "$RESOLVERS" ] && wget -q https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -O "$RESOLVERS"

# ===== MONTAGEM DOS ARGS EXTRAS POR FERRAMENTA =====
# Header: só faz sentido em ferramentas que batem direto no alvo (web app).
# gau/waybackurls/subfinder/crt.sh/puredns falam com serviços de terceiros
# (Wayback, crt.sh, resolvers DNS, APIs passivas), então não recebem o header.
HTTPX_HEADER_ARGS=()
KATANA_HEADER_ARGS=()
NUCLEI_HEADER_ARGS=()
WPSCAN_HEADER_ARGS=()
if [ -n "$CUSTOM_HEADER" ]; then
    HTTPX_HEADER_ARGS=(-H "$CUSTOM_HEADER")
    KATANA_HEADER_ARGS=(-H "$CUSTOM_HEADER")
    NUCLEI_HEADER_ARGS=(-H "$CUSTOM_HEADER")
    WPSCAN_HEADER_ARGS=(--headers "$CUSTOM_HEADER")
fi

# Rate limit: aplicado em todas as ferramentas que suportam o conceito.
SUBFINDER_RATE_ARGS=()
PUREDNS_RATE_ARGS=()
HTTPX_RATE_ARGS=()
KATANA_RATE_ARGS=()
NUCLEI_RATE_ARGS=()
GAU_RATE_ARGS=(--threads 50)   # valor padrão caso -R não seja informado
WPSCAN_RATE_ARGS=()
if [ -n "$MAX_RPS" ]; then
    SUBFINDER_RATE_ARGS=(-rate-limit "$MAX_RPS")
    PUREDNS_RATE_ARGS=(--rate-limit "$MAX_RPS")
    HTTPX_RATE_ARGS=(-rate-limit "$MAX_RPS")
    KATANA_RATE_ARGS=(-rate-limit "$MAX_RPS")
    NUCLEI_RATE_ARGS=(-rate-limit "$MAX_RPS")
    GAU_RATE_ARGS=(--threads "$MAX_RPS")
    # wpscan não tem "requisições/segundo" direto, usa --throttle em ms entre requests
    THROTTLE_MS=$(( 1000 / MAX_RPS ))
    [ "$THROTTLE_MS" -lt 1 ] && THROTTLE_MS=1
    WPSCAN_RATE_ARGS=(--throttle "$THROTTLE_MS")
fi

print_banner "RECON INICIADO: $DOMAIN"
echo -e "${CYAN}Workspace: $WORK${RESET}"
[ -n "$CUSTOM_HEADER" ] && echo -e "${CYAN}Header customizado: $CUSTOM_HEADER${RESET}"
[ -n "$MAX_RPS" ] && echo -e "${CYAN}Rate limit: $MAX_RPS req/s${RESET}"

# ===== FASE 1: SUBDOMÍNIOS =====
print_banner "FASE 1: Subdomínios"
subfinder -d "$DOMAIN" "${SUBFINDER_RATE_ARGS[@]}" -silent > "$WORK/subs_passive.txt"
curl -s "https://crt.sh/?q=%.$DOMAIN&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u >> "$WORK/subs_passive.txt"
sort -u "$WORK/subs_passive.txt" > "$WORK/subs_all.txt"

# ===== FASE 2: DNS =====
print_banner "FASE 2: DNS Resolve"
puredns resolve "$WORK/subs_all.txt" -r "$RESOLVERS" "${PUREDNS_RATE_ARGS[@]}" -q -w "$WORK/subs_alive.txt"
[ ! -s "$WORK/subs_alive.txt" ] && { echo -e "${RED}[X] Nenhum subdomínio vivo encontrado.${RESET}"; exit 1; }

# ===== FASE 3: WEB PROBING =====
print_banner "FASE 3: Web Probing"
# O httpx agora lê direto dos subdomínios vivos do puredns
httpx -l "$WORK/subs_alive.txt" "${HTTPX_HEADER_ARGS[@]}" "${HTTPX_RATE_ARGS[@]}" -silent -o "$WORK/final_urls.txt"
httpx -l "$WORK/subs_alive.txt" "${HTTPX_HEADER_ARGS[@]}" "${HTTPX_RATE_ARGS[@]}" -status-code -title -tech-detect -server -csv -silent -o "$WORK/tech/web_info.csv"

# ===============================
#        PÓS-RECON REAL
# ===============================

# ===== FASE 4: URLs HISTÓRICAS =====
print_banner "FASE 4: URLs HISTÓRICAS"
cat "$WORK/final_urls.txt" | gau "${GAU_RATE_ARGS[@]}" | anew "$WORK/urls/historical.txt"
cat "$WORK/final_urls.txt" | waybackurls | anew "$WORK/urls/historical.txt"

# ===== FASE 5: CRAWLING ATIVO =====
print_banner "FASE 5: CRAWLING ATIVO"
katana -list "$WORK/final_urls.txt" "${KATANA_HEADER_ARGS[@]}" "${KATANA_RATE_ARGS[@]}" -silent -jc -d 2 -o "$WORK/urls/crawled.txt"

cat "$WORK/urls/"*.txt | sort -u > "$WORK/urls/all_urls.txt"

# ===== FASE 6: JAVASCRIPT & SEGREDOS (NOVO) =====
print_banner "FASE 6: ANÁLISE DE JAVASCRIPT"
grep "\.js$" "$WORK/urls/all_urls.txt" | sort -u > "$WORK/urls/js_files.txt"
if [ -s "$WORK/urls/js_files.txt" ]; then
    echo -e "${YELLOW}Buscando chaves de API e Segredos em arquivos JS...${RESET}"
    nuclei -l "$WORK/urls/js_files.txt" "${NUCLEI_HEADER_ARGS[@]}" "${NUCLEI_RATE_ARGS[@]}" -tags exposure,token,key,api -silent -o "$WORK/tech/js_secrets.txt"
fi

# ===== FASE 7: CMS & WPSCAN (NOVO) =====
print_banner "FASE 7: DETECÇÃO DE WORDPRESS"
grep -i "wordpress" "$WORK/tech/web_info.csv" | awk -F ',' '{print $1}' > "$WORK/cms/wp_targets.txt"
if [ -s "$WORK/cms/wp_targets.txt" ]; then
    echo -e "${YELLOW}[!] WordPress detectado. Iniciando wpscan passivo...${RESET}"
    for wp_url in $(cat "$WORK/cms/wp_targets.txt"); do
        wpscan --url "$wp_url" "${WPSCAN_HEADER_ARGS[@]}" "${WPSCAN_RATE_ARGS[@]}" --random-user-agent --format cli-no-color --batch >> "$WORK/cms/wpscan_results.txt"
    done
fi

# ===== FASE 8: PARÂMETROS =====
print_banner "FASE 8: EXTRAÇÃO DE PARÂMETROS"
grep "=" "$WORK/urls/all_urls.txt" | sort -u > "$WORK/params/params.txt"

# ===== FASE 9: CLASSIFICAÇÃO DE VETORES =====
print_banner "FASE 9: CLASSIFICAÇÃO DE VETORES"
cat "$WORK/params/params.txt" | gf xss > "$WORK/vectors/xss.txt"
cat "$WORK/params/params.txt" | gf sqli > "$WORK/vectors/sqli.txt"
cat "$WORK/params/params.txt" | gf ssrf > "$WORK/vectors/ssrf.txt"
cat "$WORK/params/params.txt" | gf lfi > "$WORK/vectors/lfi.txt"
cat "$WORK/params/params.txt" | gf redirect > "$WORK/vectors/redirect.txt"

# ===== FASE 10: HEADERS =====
print_banner "FASE 10: HEADERS SENSÍVEIS"
httpx -l "$WORK/final_urls.txt" "${HTTPX_HEADER_ARGS[@]}" "${HTTPX_RATE_ARGS[@]}" -json -silent | jq -r 'select(.headers) | .url + " => " + (.headers|tostring)' > "$WORK/tech/headers.txt"

# ===== FASE 11: NUCLEI =====
print_banner "FASE 11: NUCLEI"
nuclei -l "$WORK/final_urls.txt" "${NUCLEI_HEADER_ARGS[@]}" "${NUCLEI_RATE_ARGS[@]}" -severity critical,high,medium -tags cve,misconfig -silent -o "$WORK/nuclei.txt"

# ===== RESUMO =====
print_banner "RESUMO FINAL"
echo -e "📂 Workspace: $WORK"
echo -e "🌐 URLs Web: $(wc -l < $WORK/final_urls.txt)"
echo -e "🔗 URLs totais (hist + crawl): $(wc -l < $WORK/urls/all_urls.txt)"
echo -e "📜 Arquivos JS: $(wc -l < $WORK/urls/js_files.txt)"
echo -e "🧪 Params: $(wc -l < $WORK/params/params.txt)"
[ -f "$WORK/tech/js_secrets.txt" ] && echo -e "🔑 JS Secrets: $(wc -l < $WORK/tech/js_secrets.txt)"
[ -f "$WORK/cms/wpscan_results.txt" ] && echo -e "📝 WPScan Concluído!"
echo -e "💥 Vulns (nuclei): $(wc -l < $WORK/nuclei.txt)"
[ -n "$CUSTOM_HEADER" ] && echo -e "🏷️  Header usado: $CUSTOM_HEADER"
[ -n "$MAX_RPS" ] && echo -e "⏱️  Rate limit usado: $MAX_RPS req/s"