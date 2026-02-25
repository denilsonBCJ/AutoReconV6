#!/bin/bash

# ==========================================
#  AUTOMAÇÃO RECON + PÓS-RECON (BUG BOUNTY)
#  Versão: 6.0 (No-PortScan & Deep CMS/JS Edition)
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

[ -z "$1" ] && { echo "Uso: ./automator_v6.sh alvo.com"; exit 1; }

check_tools

DOMAIN=$(echo "$1" | sed 's|https\?://||;s|/$||')
DATE=$(date +%F)
WORK="$DOMAIN/recon_$DATE"
mkdir -p "$WORK"/{urls,params,vectors,tech,cms}

RESOLVERS="$WORK/resolvers.txt"
[ ! -f "$RESOLVERS" ] && wget -q https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -O "$RESOLVERS"

print_banner "RECON INICIADO: $DOMAIN"
echo -e "${CYAN}Workspace: $WORK${RESET}"

# ===== FASE 1: SUBDOMÍNIOS =====
print_banner "FASE 1: Subdomínios"
subfinder -d "$DOMAIN" -silent > "$WORK/subs_passive.txt"
curl -s "https://crt.sh/?q=%.$DOMAIN&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u >> "$WORK/subs_passive.txt"
sort -u "$WORK/subs_passive.txt" > "$WORK/subs_all.txt"

# ===== FASE 2: DNS =====
print_banner "FASE 2: DNS Resolve"
puredns resolve "$WORK/subs_all.txt" -r "$RESOLVERS" -q -w "$WORK/subs_alive.txt"
[ ! -s "$WORK/subs_alive.txt" ] && { echo -e "${RED}[X] Nenhum subdomínio vivo encontrado.${RESET}"; exit 1; }

# ===== FASE 3: WEB PROBING =====
print_banner "FASE 3: Web Probing"
# O httpx agora lê direto dos subdomínios vivos do puredns
httpx -l "$WORK/subs_alive.txt" -silent -o "$WORK/final_urls.txt"
httpx -l "$WORK/subs_alive.txt" -status-code -title -tech-detect -server -csv -silent -o "$WORK/tech/web_info.csv"

# ===============================
#        PÓS-RECON REAL
# ===============================

# ===== FASE 4: URLs HISTÓRICAS =====
print_banner "FASE 4: URLs HISTÓRICAS"
cat "$WORK/final_urls.txt" | gau --threads 50 | anew "$WORK/urls/historical.txt"
cat "$WORK/final_urls.txt" | waybackurls | anew "$WORK/urls/historical.txt"

# ===== FASE 5: CRAWLING ATIVO =====
print_banner "FASE 5: CRAWLING ATIVO"
katana -list "$WORK/final_urls.txt" -silent -jc -d 2 -o "$WORK/urls/crawled.txt"

cat "$WORK/urls/"*.txt | sort -u > "$WORK/urls/all_urls.txt"

# ===== FASE 6: JAVASCRIPT & SEGREDOS (NOVO) =====
print_banner "FASE 6: ANÁLISE DE JAVASCRIPT"
grep "\.js$" "$WORK/urls/all_urls.txt" | sort -u > "$WORK/urls/js_files.txt"
if [ -s "$WORK/urls/js_files.txt" ]; then
    echo -e "${YELLOW}Buscando chaves de API e Segredos em arquivos JS...${RESET}"
    nuclei -l "$WORK/urls/js_files.txt" -tags exposure,token,key,api -silent -o "$WORK/tech/js_secrets.txt"
fi

# ===== FASE 7: CMS & WPSCAN (NOVO) =====
print_banner "FASE 7: DETECÇÃO DE WORDPRESS"
grep -i "wordpress" "$WORK/tech/web_info.csv" | awk -F ',' '{print $1}' > "$WORK/cms/wp_targets.txt"
if [ -s "$WORK/cms/wp_targets.txt" ]; then
    echo -e "${YELLOW}[!] WordPress detectado. Iniciando wpscan passivo...${RESET}"
    for wp_url in $(cat "$WORK/cms/wp_targets.txt"); do
        wpscan --url "$wp_url" --random-user-agent --format cli-no-color --batch >> "$WORK/cms/wpscan_results.txt"
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
httpx -l "$WORK/final_urls.txt" -json -silent | jq -r 'select(.headers) | .url + " => " + (.headers|tostring)' > "$WORK/tech/headers.txt"

# ===== FASE 11: NUCLEI =====
print_banner "FASE 11: NUCLEI"
nuclei -l "$WORK/final_urls.txt" -severity critical,high,medium -tags cve,misconfig -silent -o "$WORK/nuclei.txt"

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