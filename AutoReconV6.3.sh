#!/bin/bash

# ==========================================
#  AUTOMAÇÃO RECON + PÓS-RECON (BUG BOUNTY)
#  Versão: 6.3 (Parallel & Low-Noise Edition)
#
#  Mudanças vs 6.2:
#   - Fase 4+5 e Fase 6+7 agora rodam em paralelo (jobs em background + wait)
#   - wpscan paralelizado via xargs -P (antes: for loop sequencial)
#   - -threads/-c explícitos em httpx/katana/nuclei (defaults eram conservadores)
#   - gau/waybackurls recebem domínios nus (subs_alive.txt), não URLs com scheme
#   - final_urls.txt filtrado por status code relevante (-mc) antes das fases pesadas
#   - katana exclui extensões estáticas (imagens/css/fonts) do crawl
#   - Dedup de params por assinatura (path + nomes) antes da Fase 9 — menos ruído/volume
#   - Padrões gf custom (nosqli/xxe/crlf/ldap) reescritos com termos de maior precisão
#   - crlf.txt deduplicado contra redirect.txt (eram quase idênticos antes)
# ==========================================

# ===== CORES =====
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RESET='\033[0m'

# ===== CONCORRÊNCIA (ajuste conforme CPU/banda) =====
HTTPX_THREADS=50
KATANA_CONCURRENCY=20
NUCLEI_CONCURRENCY=25
WPSCAN_PARALLEL=3

# Status codes considerados "vivos/relevantes" para final_urls.txt
# (usado para crawling, historical merge-check, nuclei, headers — não afeta o CSV completo de tech-detect)
LIVE_STATUS_CODES="200,201,204,301,302,307,308,401,403"

# Extensões estáticas excluídas do crawl ativo (katana) — reduz ruído/tempo
STATIC_EXT="png,jpg,jpeg,gif,svg,css,woff,woff2,ttf,eot,ico,mp4,mp3,pdf"

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
        gau waybackurls gf anew wpscan xargs
    )
    for tool in "${REQUIRED_TOOLS[@]}"; do
        command -v $tool &>/dev/null || {
            echo -e "${RED}[X] Ferramenta ausente: $tool${RESET}"
            exit 1
        }
    done
}

# ===== PATTERNS CUSTOMIZADOS DO GF =====
# xss, sqli, lfi, ssrf e redirect já vêm prontos do setup do README (tomnomnom/gf +
# 1ndianl33t/Gf-Patterns), junto com rce.json (Command Injection) e ssti.json (SSTI).
# NoSQLi, XXE, CRLF/Header Injection e LDAP Injection não existem em nenhum pacote
# público de gf — o script cria esses patterns sozinho em ~/.gf (só se ainda não
# existirem). v6.3: termos genéricos (id, user, search, path, login...) foram
# removidos — eles casavam com quase qualquer parâmetro e geravam ruído massivo.
# Os patterns agora priorizam termos de alta precisão para cada classe de vuln.
ensure_custom_gf_patterns() {
    mkdir -p "$HOME/.gf"

    if [ ! -f "$HOME/.gf/nosqli.json" ]; then
        cat > "$HOME/.gf/nosqli.json" << 'EOF'
{
    "flags": "-iE",
    "patterns": [
        "mongo",
        "nosql",
        "aggregate",
        "pipeline",
        "projection",
        "collection",
        "\\$where",
        "\\$regex",
        "\\$ne",
        "\\$gt",
        "\\$in"
    ]
}
EOF
    fi

    if [ ! -f "$HOME/.gf/xxe.json" ]; then
        cat > "$HOME/.gf/xxe.json" << 'EOF'
{
    "flags": "-iE",
    "patterns": [
        "xml",
        "wsdl",
        "soap",
        "xsd",
        "svg",
        "rss",
        "atom",
        "dtd",
        "entity"
    ]
}
EOF
    fi

    if [ ! -f "$HOME/.gf/crlf.json" ]; then
        cat > "$HOME/.gf/crlf.json" << 'EOF'
{
    "flags": "-iE",
    "patterns": [
        "redirect",
        "location",
        "url",
        "callback",
        "lang",
        "host"
    ]
}
EOF
    fi

    if [ ! -f "$HOME/.gf/ldap.json" ]; then
        cat > "$HOME/.gf/ldap.json" << 'EOF'
{
    "flags": "-iE",
    "patterns": [
        "ldap",
        "bind",
        "dn=",
        "cn=",
        "ou=",
        "base=",
        "uid="
    ]
}
EOF
    fi
}
fetch_crtsh() {
    local domain="$1" attempt json
    for attempt in 1 2 3; do
        json=$(curl -s --max-time 20 "https://crt.sh/?q=%.$domain&output=json")
        if echo "$json" | jq -e . >/dev/null 2>&1; then
            echo "$json"
            return 0
        fi
        sleep 2
    done
    return 1
}
# Roda "gf <pattern>" se o arquivo de pattern existir em ~/.gf; senão avisa e
# gera um arquivo de saída vazio, sem travar o resto do pipeline.
gf_classify() {
    local pattern_name="$1"
    local out_file="$2"
    if [ -f "$HOME/.gf/${pattern_name}.json" ]; then
        gf "$pattern_name" < "$WORK/params/params.txt" > "$out_file"
    else
        echo -e "${YELLOW}[!] Padrão gf '$pattern_name' não encontrado em ~/.gf — pulando essa classe.${RESET}"
        : > "$out_file"
    fi
}

# wpscan isolado p/ uso em paralelo (xargs -P). Lê header/throttle de env vars
# escalares (CUSTOM_HEADER / THROTTLE_MS) em vez de arrays, que não são
# exportáveis entre processos bash.
run_wpscan_one() {
    local wp_url="$1"
    local args=()
    [ -n "$CUSTOM_HEADER" ] && args+=(--headers "$CUSTOM_HEADER")
    [ -n "$THROTTLE_MS" ] && args+=(--throttle "$THROTTLE_MS")
    local safe
    safe=$(echo "$wp_url" | tr -c '[:alnum:]' '_')
    wpscan --url "$wp_url" "${args[@]}" --random-user-agent --format cli-no-color --batch \
        > "$WORK/cms/wpscan_out/$safe.txt" 2>&1
}
export -f run_wpscan_one

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
ensure_custom_gf_patterns

DOMAIN=$(echo "$TARGET" | sed 's|https\?://||;s|/$||')
DATE=$(date +%F)
WORK="$DOMAIN/recon_$DATE"
mkdir -p "$WORK"/{urls,params,vectors,tech,cms}

RESOLVERS="$WORK/resolvers.txt"
[ ! -f "$RESOLVERS" ] && wget -q https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -O "$RESOLVERS"

# ===== MONTAGEM DOS ARGS EXTRAS POR FERRAMENTA =====
HTTPX_HEADER_ARGS=()
KATANA_HEADER_ARGS=()
NUCLEI_HEADER_ARGS=()
WPSCAN_HEADER_ARGS=()
if [ -n "$CUSTOM_HEADER" ]; then
    HTTPX_HEADER_ARGS=(-H "$CUSTOM_HEADER")
    KATANA_HEADER_ARGS=(-H "$CUSTOM_HEADER")
    NUCLEI_HEADER_ARGS=(-H "$CUSTOM_HEADER")
fi

SUBFINDER_RATE_ARGS=()
PUREDNS_RATE_ARGS=()
HTTPX_RATE_ARGS=()
KATANA_RATE_ARGS=()
NUCLEI_RATE_ARGS=()
GAU_RATE_ARGS=(--threads 50)
THROTTLE_MS=""
if [ -n "$MAX_RPS" ]; then
    SUBFINDER_RATE_ARGS=(-rate-limit "$MAX_RPS")
    PUREDNS_RATE_ARGS=(--rate-limit "$MAX_RPS")
    HTTPX_RATE_ARGS=(-rate-limit "$MAX_RPS")
    KATANA_RATE_ARGS=(-rate-limit "$MAX_RPS")
    NUCLEI_RATE_ARGS=(-rate-limit "$MAX_RPS")
    GAU_RATE_ARGS=(--threads "$MAX_RPS")
    THROTTLE_MS=$(( 1000 / MAX_RPS ))
    [ "$THROTTLE_MS" -lt 1 ] && THROTTLE_MS=1
fi
export CUSTOM_HEADER THROTTLE_MS WORK

print_banner "RECON INICIADO: $DOMAIN"
echo -e "${CYAN}Workspace: $WORK${RESET}"
[ -n "$CUSTOM_HEADER" ] && echo -e "${CYAN}Header customizado: $CUSTOM_HEADER${RESET}"
[ -n "$MAX_RPS" ] && echo -e "${CYAN}Rate limit: $MAX_RPS req/s${RESET}"

# ===== FASE 1: SUBDOMÍNIOS =====
print_banner "FASE 1: Subdomínios"
subfinder -d "$DOMAIN" "${SUBFINDER_RATE_ARGS[@]}" -silent > "$WORK/subs_passive.txt"
CRTSH_JSON=$(fetch_crtsh "$DOMAIN")
if [ $? -eq 0 ]; then
    echo "$CRTSH_JSON" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u >> "$WORK/subs_passive.txt"
else
    echo -e "${YELLOW}[!] crt.sh indisponível após 3 tentativas — seguindo só com subfinder.${RESET}"
fi
sort -u "$WORK/subs_passive.txt" > "$WORK/subs_all.txt"

# ===== FASE 2: DNS =====
print_banner "FASE 2: DNS Resolve"
puredns resolve "$WORK/subs_all.txt" -r "$RESOLVERS" "${PUREDNS_RATE_ARGS[@]}" -q -w "$WORK/subs_alive.txt"
[ ! -s "$WORK/subs_alive.txt" ] && { echo -e "${RED}[X] Nenhum subdomínio vivo encontrado.${RESET}"; exit 1; }

# ===== FASE 3: WEB PROBING =====
print_banner "FASE 3: Web Probing"
# final_urls.txt agora filtrado por status code relevante (LIVE_STATUS_CODES) —
# corta ruído de 404/500/timeout que antes era arrastado por todas as fases seguintes.
httpx -l "$WORK/subs_alive.txt" "${HTTPX_HEADER_ARGS[@]}" "${HTTPX_RATE_ARGS[@]}" -threads "$HTTPX_THREADS" \
    -mc "$LIVE_STATUS_CODES" -silent -o "$WORK/final_urls.txt"
# CSV de tech-detect continua sem filtro de status — é inventário, não input de ataque.
httpx -l "$WORK/subs_alive.txt" "${HTTPX_HEADER_ARGS[@]}" "${HTTPX_RATE_ARGS[@]}" -threads "$HTTPX_THREADS" \
    -status-code -title -tech-detect -server -csv -silent -o "$WORK/tech/web_info.csv"

# ===============================
#        PÓS-RECON REAL
# ===============================

# ===== FASE 4+5: COLETA DE URLs (paralelo) =====
print_banner "FASE 4+5: URLs HISTÓRICAS + CRAWLING ATIVO (paralelo)"
# gau/waybackurls agora recebem domínios nus (subs_alive.txt), não URLs com
# scheme — é o formato que essas ferramentas esperam; evita resultado degradado.
cat "$WORK/subs_alive.txt" | gau "${GAU_RATE_ARGS[@]}" > "$WORK/urls/historical_gau.txt" &
cat "$WORK/subs_alive.txt" | waybackurls > "$WORK/urls/historical_wb.txt" &
katana -list "$WORK/final_urls.txt" "${KATANA_HEADER_ARGS[@]}" "${KATANA_RATE_ARGS[@]}" -c "$KATANA_CONCURRENCY" \
    -silent -jc -d 2 -ef "$STATIC_EXT" -o "$WORK/urls/crawled.txt" &
wait

cat "$WORK/urls/historical_gau.txt" "$WORK/urls/historical_wb.txt" | anew "$WORK/urls/historical.txt" > /dev/null
cat "$WORK/urls/"*.txt | sort -u > "$WORK/urls/all_urls.txt"

# ===== FASE 6+7: JS SECRETS + WORDPRESS (paralelo) =====
print_banner "FASE 6+7: JS SECRETS + WPSCAN (paralelo)"
grep "\.js$" "$WORK/urls/all_urls.txt" | sort -u > "$WORK/urls/js_files.txt"
grep -i "wordpress" "$WORK/tech/web_info.csv" | awk -F ',' '{print $1}' > "$WORK/cms/wp_targets.txt"

if [ -s "$WORK/urls/js_files.txt" ]; then
    echo -e "${YELLOW}Buscando chaves de API e Segredos em arquivos JS...${RESET}"
    nuclei -l "$WORK/urls/js_files.txt" "${NUCLEI_HEADER_ARGS[@]}" "${NUCLEI_RATE_ARGS[@]}" -c "$NUCLEI_CONCURRENCY" \
        -tags exposure,token,key,api -silent -o "$WORK/tech/js_secrets.txt" &
fi

if [ -s "$WORK/cms/wp_targets.txt" ]; then
    echo -e "${YELLOW}[!] WordPress detectado. Iniciando wpscan (paralelo, max $WPSCAN_PARALLEL)...${RESET}"
    mkdir -p "$WORK/cms/wpscan_out"
    (cat "$WORK/cms/wp_targets.txt" | xargs -P "$WPSCAN_PARALLEL" -I{} bash -c 'run_wpscan_one "$@"' _ {}) &
fi
wait

[ -d "$WORK/cms/wpscan_out" ] && cat "$WORK/cms/wpscan_out/"*.txt > "$WORK/cms/wpscan_results.txt" 2>/dev/null

# ===== FASE 8: PARÂMETROS (com dedup por assinatura) =====
print_banner "FASE 8: EXTRAÇÃO DE PARÂMETROS"
# Antes: todas as URLs com "=" iam pra classificação, inflando os vetores com
# milhares de variações do mesmo parâmetro (id=1, id=2, id=3...). Agora: mantém
# só 1 URL exemplo por combinação única de path + nomes de parâmetros.
grep "=" "$WORK/urls/all_urls.txt" | sort -u | awk -F'?' '
{
    path = $1
    n = split($2, pairs, "&")
    sig = path "?"
    for (i = 1; i <= n; i++) {
        split(pairs[i], kv, "=")
        sig = sig kv[1] "&"
    }
    if (!(sig in seen)) {
        seen[sig] = 1
        print $0
    }
}' > "$WORK/params/params.txt"

# ===== FASE 9: CLASSIFICAÇÃO DE VETORES =====
print_banner "FASE 9: CLASSIFICAÇÃO DE VETORES"
gf_classify xss      "$WORK/vectors/xss.txt"
gf_classify sqli     "$WORK/vectors/sqli.txt"
gf_classify nosqli   "$WORK/vectors/nosqli.txt"
gf_classify rce      "$WORK/vectors/cmdi.txt"
gf_classify ssti     "$WORK/vectors/ssti.txt"
gf_classify lfi      "$WORK/vectors/lfi.txt"
gf_classify xxe      "$WORK/vectors/xxe.txt"
gf_classify ssrf     "$WORK/vectors/ssrf.txt"
gf_classify redirect "$WORK/vectors/redirect.txt"
gf_classify crlf     "$WORK/vectors/crlf_raw.txt"
gf_classify ldap     "$WORK/vectors/ldap.txt"

# crlf.json compartilha quase todos os termos com o pattern padrão "redirect" —
# sem isso, os dois arquivos eram praticamente duplicados. Mantém em crlf.txt
# só o que NÃO está em redirect.txt.
sort -u "$WORK/vectors/crlf_raw.txt" -o "$WORK/vectors/crlf_raw.txt"
sort -u "$WORK/vectors/redirect.txt" -o "$WORK/vectors/redirect_sorted.txt" 2>/dev/null || cp "$WORK/vectors/redirect.txt" "$WORK/vectors/redirect_sorted.txt"
comm -23 "$WORK/vectors/crlf_raw.txt" "$WORK/vectors/redirect_sorted.txt" > "$WORK/vectors/crlf.txt"
rm -f "$WORK/vectors/crlf_raw.txt" "$WORK/vectors/redirect_sorted.txt"

# ===== FASE 10: HEADERS =====
print_banner "FASE 10: HEADERS SENSÍVEIS"
httpx -l "$WORK/final_urls.txt" "${HTTPX_HEADER_ARGS[@]}" "${HTTPX_RATE_ARGS[@]}" -threads "$HTTPX_THREADS" \
    -json -silent | jq -r 'select(.headers) | .url + " => " + (.headers|tostring)' > "$WORK/tech/headers.txt"

# ===== FASE 11: NUCLEI =====
print_banner "FASE 11: NUCLEI"
nuclei -l "$WORK/final_urls.txt" "${NUCLEI_HEADER_ARGS[@]}" "${NUCLEI_RATE_ARGS[@]}" -c "$NUCLEI_CONCURRENCY" \
    -severity critical,high,medium -tags cve,misconfig -silent -o "$WORK/nuclei.txt"

# ===== RESUMO =====
print_banner "RESUMO FINAL"
echo -e "📂 Workspace: $WORK"
echo -e "🌐 URLs Web (live, filtradas): $(wc -l < $WORK/final_urls.txt)"
echo -e "🔗 URLs totais (hist + crawl): $(wc -l < $WORK/urls/all_urls.txt)"
echo -e "📜 Arquivos JS: $(wc -l < $WORK/urls/js_files.txt)"
echo -e "🧪 Params (deduplicados): $(wc -l < $WORK/params/params.txt)"
[ -f "$WORK/tech/js_secrets.txt" ] && echo -e "🔑 JS Secrets: $(wc -l < $WORK/tech/js_secrets.txt)"
[ -f "$WORK/cms/wpscan_results.txt" ] && echo -e "📝 WPScan Concluído!"
echo -e "💥 Vulns (nuclei): $(wc -l < $WORK/nuclei.txt)"
echo -e "🧬 Vetores classificados:"
for v in xss sqli nosqli cmdi ssti lfi xxe ssrf redirect crlf ldap; do
    vfile="$WORK/vectors/$v.txt"
    [ -f "$vfile" ] && echo -e "   - $v: $(wc -l < "$vfile")"
done
[ -n "$CUSTOM_HEADER" ] && echo -e "🏷️  Header usado: $CUSTOM_HEADER"
[ -n "$MAX_RPS" ] && echo -e "⏱️  Rate limit usado: $MAX_RPS req/s"