#!/usr/bin/env bash
# check-dump-assumptions.sh
# Быстрая проверка допущений алгоритма «CRD от дампа» на живом кластере с Istio.
# Linux, bash 4+. Нужны: kubectl, jq, curl (apt install jq curl / dnf install jq curl).
# Только чтение: get/list, pods/proxy GET (syncz), pods/portforward на Envoy admin.
# Запускать с машины, где есть kubeconfig; локальный порт LOCAL_PORT должен быть свободен.
#
# Использование:
#   SRC_NS=default SRC_WORKLOAD=productpage-v1 \
#   DST_HOST=reviews.default.svc.cluster.local DST_PORT=9080 \
#   bash check-dump-assumptions.sh
#
# Статусы: PASS / FAIL / UNKNOWN (в кластере нет ресурса для проверки).

set -u

SRC_NS="${SRC_NS:-default}"
SRC_WORKLOAD="${SRC_WORKLOAD:-productpage-v1}"
DST_HOST="${DST_HOST:-reviews.default.svc.cluster.local}"
DST_PORT="${DST_PORT:-9080}"
ISTIO_NS="${ISTIO_NS:-istio-system}"
LOCAL_PORT="${LOCAL_PORT:-15099}"
KCTX="${KCTX:-}"
OUT="${OUT:-./out/$(date +%Y%m%d-%H%M%S)}"

mkdir -p "$OUT"
RESULTS="$OUT/results.txt"
: > "$RESULTS"

K() { if [ -n "$KCTX" ]; then kubectl --context "$KCTX" "$@"; else kubectl "$@"; fi; }
res() { printf '%-4s %-8s %s\n' "$1" "$2" "$3" | tee -a "$RESULTS"; }
log() { printf '\n== %s\n' "$*"; }
fsize() { wc -c < "$1" | tr -d ' '; }
die() { echo "FATAL: $*" >&2; exit 1; }

for t in kubectl jq curl; do
  command -v "$t" >/dev/null 2>&1 || die "нет $t (apt install $t)"
done

# ---------- port-forward ----------
PF_PID=""
pf_start() { # ns pod
  K -n "$1" port-forward "pod/$2" "$LOCAL_PORT:15000" > "$OUT/pf-$2.log" 2>&1 &
  PF_PID=$!
  i=0
  while [ $i -lt 40 ]; do
    if curl -sf "http://127.0.0.1:$LOCAL_PORT/ready" >/dev/null 2>&1; then return 0; fi
    sleep 0.25; i=$((i+1))
  done
  echo "port-forward к $1/$2 не поднялся:"; cat "$OUT/pf-$2.log"
  return 1
}
pf_stop() { if [ -n "$PF_PID" ]; then kill "$PF_PID" 2>/dev/null; wait "$PF_PID" 2>/dev/null; PF_PID=""; fi; }
trap pf_stop EXIT
fetch() { # path outfile -> time_total
  curl -s -o "$2" -w '%{time_total}' "http://127.0.0.1:$LOCAL_PORT$1"
}

# ---------- участники ----------
log "Участники"
case "$DST_HOST" in
  *.*) ;;
  *) DST_HOST="$DST_HOST.$SRC_NS.svc.cluster.local" ;;
esac
DST_SVC="${DST_HOST%%.*}"
_rest="${DST_HOST#*.}"
DST_NS="${_rest%%.*}"

sel=$(K -n "$SRC_NS" get deploy "$SRC_WORKLOAD" -o json 2>/dev/null \
  | jq -r '.spec.selector.matchLabels | to_entries | map("\(.key)=\(.value)") | join(",")')
[ -n "$sel" ] || die "deployment $SRC_NS/$SRC_WORKLOAD не найден"
SRC_POD=$(K -n "$SRC_NS" get pod -l "$sel" --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
[ -n "$SRC_POD" ] || die "нет Running pod'а для $SRC_NS/$SRC_WORKLOAD"

dsel=$(K -n "$DST_NS" get svc "$DST_SVC" -o json 2>/dev/null \
  | jq -r '.spec.selector // {} | to_entries | map("\(.key)=\(.value)") | join(",")')
DST_POD=""
if [ -n "$dsel" ]; then
  DST_POD=$(K -n "$DST_NS" get pod -l "$dsel" --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
fi
echo "A: $SRC_NS/$SRC_POD"
echo "B: $DST_HOST:$DST_PORT  ns=$DST_NS svc=$DST_SVC pod=${DST_POD:-<не найден>}"

# ---------- A1 RBAC ----------
log "A1 RBAC"
can() { [ "$(K auth can-i "$@" 2>/dev/null)" = "yes" ]; }
a1=PASS; msg=""
can create pods --subresource=portforward -n "$SRC_NS" || { a1=FAIL; msg="$msg no:pods/portforward"; }
can get pods --subresource=log -n "$SRC_NS"            || { a1=FAIL; msg="$msg no:pods/log"; }
can get pods --subresource=proxy -n "$ISTIO_NS"         || { a1=FAIL; msg="$msg no:pods/proxy"; }
if can list virtualservices.networking.istio.io -A; then msg="$msg cluster-list:yes"; else msg="$msg cluster-list:no(ок, уровень cluster будет недоступен)"; fi
res A1 "$a1" "${msg# }"

# ---------- A2 дамп с масками ----------
log "A2 дамп pod'а A с масками"
pf_start "$SRC_NS" "$SRC_POD" || { res A2 FAIL "port-forward не поднялся"; exit 1; }
L="$OUT/A-listeners.json"; R="$OUT/A-routes.json"; C="$OUT/A-clusters.json"; E="$OUT/A-endpoints.json"; F="$OUT/A-full.json"; NR="$OUT/A-clusters-regex.json"
tL=$(fetch "/config_dump?resource=dynamic_listeners" "$L")
tR=$(fetch "/config_dump?resource=dynamic_route_configs" "$R")
tC=$(fetch "/config_dump?resource=dynamic_active_clusters" "$C")
tE=$(fetch "/config_dump?resource=dynamic_endpoint_configs&include_eds=true" "$E")
tF=$(fetch "/config_dump?include_eds=true" "$F")
tN=$(fetch "/config_dump?resource=dynamic_active_clusters&name_regex=.*${DST_SVC}.*" "$NR")
printf '%-10s %10s bytes %6ss\n' listeners "$(fsize "$L")" "$tL"
printf '%-10s %10s bytes %6ss\n' routes    "$(fsize "$R")" "$tR"
printf '%-10s %10s bytes %6ss\n' clusters  "$(fsize "$C")" "$tC"
printf '%-10s %10s bytes %6ss\n' endpoints "$(fsize "$E")" "$tE"
printf '%-10s %10s bytes %6ss\n' full      "$(fsize "$F")" "$tF"
printf '%-10s %10s bytes %6ss\n' name_regex "$(fsize "$NR")" "$tN"
a2=PASS; msg=""
for f in "$L" "$R" "$C" "$E"; do
  n=$(jq '.configs | length' "$f" 2>/dev/null || echo 0)
  [ "$n" = "1" ] || { a2=FAIL; msg="$msg mask-failed:$(basename "$f")"; }
done
ncl_all=$(jq '[.configs[].dynamic_active_clusters[]?] | length' "$C")
ncl_rx=$(jq '[.configs[].dynamic_active_clusters[]?] | length' "$NR")
[ "$ncl_rx" -lt "$ncl_all" ] 2>/dev/null || { a2=FAIL; msg="$msg name_regex-no-effect"; }
masked=$(( $(fsize "$L") + $(fsize "$R") + $(fsize "$C") + $(fsize "$E") ))
[ "$masked" -lt "$(fsize "$F")" ] || msg="$msg masked>=full"
res A2 "$a2" "clusters all=$ncl_all regex=$ncl_rx masked=${masked}B full=$(fsize "$F")B${msg}"

# ---------- A12/A3 путь: listener -> RDS -> vhost -> routes ----------
log "A12/A3 путь A->B"
LNAME=$(jq -r --arg p "$DST_PORT" '
  [.configs[].dynamic_listeners[]? | select(.name == ("0.0.0.0_"+$p) or (.name | endswith("_"+$p))) | .name] | first // empty' "$L")
echo "listener: ${LNAME:-<нет>}"
RDS=$(jq -r --arg n "$LNAME" '
  [.configs[].dynamic_listeners[]? | select(.name == $n) | .. | objects
   | select(.name? == "envoy.filters.network.http_connection_manager")
   | .typed_config.rds.route_config_name? // empty] | unique | first // empty' "$L")
echo "rds: ${RDS:-<нет, порт не HTTP или listener другой>}"
jq --arg h "$DST_HOST" --arg p "$DST_PORT" --arg r "$RDS" '
  [.configs[].dynamic_route_configs[]? | select(.route_config.name == $r)
   | .route_config.virtual_hosts[] | select(any(.domains[]; . == $h or . == ($h+":"+$p)))
   | {vhost: .name, routes: [.routes[] | {
        cluster: (.route.cluster // ((.route.weighted_clusters.clusters // []) | map(.name) | join(","))),
        config: .metadata.filter_metadata.istio.config}]}]' "$R" > "$OUT/A-path-routes.json"
cat "$OUT/A-path-routes.json"
nvh=$(jq 'length' "$OUT/A-path-routes.json")
nroutes=$(jq '[.[].routes[]] | length' "$OUT/A-path-routes.json")
nvs=$(jq '[.[].routes[] | .config // empty | select(test("/virtual-service/"))] | length' "$OUT/A-path-routes.json")
if [ "$nvs" -gt 0 ]; then res A3 PASS "routes=$nroutes с VS-ссылкой=$nvs: $(jq -r '[.[].routes[].config // empty] | unique | join(" ")' "$OUT/A-path-routes.json")"
elif [ "$nroutes" -gt 0 ]; then res A3 UNKNOWN "routes=$nroutes, ни одной ссылки на VS: создайте VS на $DST_HOST и повторите"
else res A3 FAIL "vhost для $DST_HOST в RDS '$RDS' не найден"; fi

# ---------- A4/A5 clusters ----------
log "A4/A5 clusters"
jq --arg h "$DST_HOST" --arg p "$DST_PORT" '
  [.configs[].dynamic_active_clusters[]? | select(.cluster.name | startswith("outbound|"+$p+"|") and endswith("|"+$h))
   | {name: .cluster.name, config: .cluster.metadata.filter_metadata.istio.config,
      services: .cluster.metadata.filter_metadata.istio.services, version_info, last_updated}]' "$C" > "$OUT/A-path-clusters.json"
cat "$OUT/A-path-clusters.json"
ncl=$(jq 'length' "$OUT/A-path-clusters.json")
ndr=$(jq '[.[] | .config // empty | select(test("/destination-rule/"))] | length' "$OUT/A-path-clusters.json")
nsvc=$(jq '[.[] | .services // empty] | length' "$OUT/A-path-clusters.json")
if [ "$ncl" -eq 0 ]; then res A4 FAIL "кластеров для $DST_HOST:$DST_PORT нет"
elif [ "$ndr" -gt 0 ]; then res A4 PASS "clusters=$ncl с DR-ссылкой=$ndr"
else res A4 UNKNOWN "clusters=$ncl, ссылок на DR нет: создайте DR с subset на $DST_HOST и повторите"; fi
if [ "$nsvc" -gt 0 ]; then res A5 PASS "istio.services есть у $nsvc из $ncl"; else res A5 FAIL "istio.services нет"; fi

# ---------- A12 endpoints ----------
nep=$(jq --arg c "outbound|$DST_PORT||$DST_HOST" '
  [.configs[].dynamic_endpoint_configs[]? | select(.endpoint_config.cluster_name == $c)
   | .endpoint_config.endpoints[]?.lb_endpoints[]?] | length' "$E")
echo "endpoints outbound|$DST_PORT||$DST_HOST: $nep"
if [ -n "$LNAME" ] && [ -n "$RDS" ] && [ "$nvh" -gt 0 ] && [ "$ncl" -gt 0 ] && [ "$nep" -gt 0 ]; then
  res A12 PASS "listener=$LNAME rds=$RDS vhosts=$nvh clusters=$ncl endpoints=$nep"
else
  res A12 FAIL "listener=${LNAME:-?} rds=${RDS:-?} vhosts=$nvh clusters=$ncl endpoints=$nep"
fi

# ---------- A6 last_updated ----------
log "A6 last_updated / version_info"
nl=$(jq '[.configs[].dynamic_listeners[]? | select(.active_state.last_updated and .active_state.version_info)] | length' "$L")
nr=$(jq '[.configs[].dynamic_route_configs[]? | select(.last_updated and .version_info)] | length' "$R")
nc=$(jq '[.configs[].dynamic_active_clusters[]? | select(.last_updated and .version_info)] | length' "$C")
if [ "$nl" -gt 0 ] && [ "$nr" -gt 0 ] && [ "$nc" -gt 0 ]; then res A6 PASS "listeners=$nl routes=$nr clusters=$nc"; else res A6 FAIL "listeners=$nl routes=$nr clusters=$nc"; fi

# ---------- A7 Sidecar в дампе ----------
log "A7 Sidecar-ресурс"
nsc=$(K get sidecars.networking.istio.io -A --no-headers 2>/dev/null | wc -l | tr -d ' ')
refs=$(grep -o '"/apis/[^"]*/sidecar/[^"]*"' "$F" | sort -u | head -5 | tr '\n' ' ')
if [ "$nsc" = "0" ]; then res A7 UNKNOWN "Sidecar-ресурсов в кластере нет; создайте Sidecar в $SRC_NS и повторите"
elif [ -n "$refs" ]; then res A7 FAIL "имя Sidecar ЕСТЬ в дампе (переносим на уровень refs): $refs"
else res A7 PASS "Sidecar в кластере: $nsc, ссылок в дампе нет, виден только эффект"; fi

# ---------- A11 get по ссылке ----------
log "A11 get по ссылкам istio.config"
grep -o '"/apis/[^"]*"' "$F" | tr -d '"' | sort -u > "$OUT/A-refs.txt"
a11=PASS; got=0; total=0
while IFS= read -r ref; do
  [ -n "$ref" ] || continue
  total=$((total+1))
  grp=$(echo "$ref" | cut -d/ -f3)
  ns=$(echo "$ref" | cut -d/ -f6)
  kind=$(echo "$ref" | cut -d/ -f7 | tr -d '-')
  name=$(echo "$ref" | cut -d/ -f8)
  rv=$(K -n "$ns" get "$kind.$grp" "$name" -o jsonpath='{.metadata.resourceVersion}' 2>/dev/null)
  if [ -n "$rv" ]; then got=$((got+1)); echo "ok   $ref rv=$rv"; else a11=FAIL; echo "FAIL $ref"; fi
done < "$OUT/A-refs.txt"
[ "$total" -gt 0 ] || a11=UNKNOWN
res A11 "$a11" "получено $got из $total ссылок"
pf_stop

# ---------- A8/A9 inbound pod'а B ----------
log "A8/A9 inbound pod'а B"
if [ -z "$DST_POD" ]; then
  res A8 UNKNOWN "pod для $DST_HOST не найден"; res A9 UNKNOWN "pod для $DST_HOST не найден"
elif pf_start "$DST_NS" "$DST_POD"; then
  IB="$OUT/B-inbound.json"
  fetch "/config_dump?resource=dynamic_listeners&name_regex=virtualInbound" "$IB" >/dev/null
  modes=$(jq -r --argjson p "$DST_PORT" '
    [.configs[].dynamic_listeners[]? | select(.name == "virtualInbound")
     | .active_state.listener.filter_chains[] | select(.filter_chain_match.destination_port == $p)
     | .filter_chain_match.transport_protocol // "any"] | unique | join(",")' "$IB")
  pa=$(grep -c -e 'peer-authentication' -e 'peerauthentication' "$IB" || true)
  case "$modes" in
    *tls*raw_buffer*|*raw_buffer*tls*) mode=PERMISSIVE ;;
    *tls*) mode=STRICT ;;
    *raw_buffer*) mode=DISABLE ;;
    *) mode="?" ;;
  esac
  if [ -n "$modes" ] && [ "$pa" = "0" ]; then res A8 PASS "port $DST_PORT transport_protocol=[$modes] => $mode; имени PeerAuth в дампе нет"
  elif [ -z "$modes" ]; then res A8 FAIL "filter chain для порта $DST_PORT в virtualInbound не найден"
  else res A8 FAIL "в дампе есть упоминание PeerAuthentication ($pa), допущение неверно"; fi

  pol=$(jq -r '[.. | objects | select(.name? == "envoy.filters.http.rbac") | (.typed_config.rules.policies // {}) | keys[]] | unique | join(" ")' "$IB")
  nap=$(K -n "$DST_NS" get authorizationpolicies.security.istio.io --no-headers 2>/dev/null | wc -l | tr -d ' ')
  if [ "$nap" = "0" ]; then res A9 UNKNOWN "AuthorizationPolicy в $DST_NS нет; создайте и повторите"
  elif echo "$pol" | grep -q 'ns\[.*\]-policy\[.*\]'; then res A9 PASS "policy ids: $pol"
  else res A9 FAIL "AuthPolicy есть ($nap), но id вида ns[..]-policy[..] в RBAC нет: '$pol'"; fi
  pf_stop
else
  res A8 FAIL "port-forward к $DST_NS/$DST_POD не поднялся"; res A9 FAIL "см. A8"
fi

# ---------- A10 syncz ----------
log "A10 syncz через pods/proxy"
a10=FAIL; found=""
for ip in $(K -n "$ISTIO_NS" get pod -l app=istiod -o jsonpath='{.items[*].metadata.name}'); do
  if K get --raw "/api/v1/namespaces/$ISTIO_NS/pods/$ip:15014/proxy/debug/syncz" > "$OUT/syncz-$ip.json" 2>/dev/null; then
    rec=$(jq -c --arg p "$SRC_POD.$SRC_NS" '[.[] | select(.proxy == $p)] | first // empty' "$OUT/syncz-$ip.json")
    if [ -n "$rec" ]; then a10=PASS; found="$ip $rec"; break; fi
  else
    echo "pods/proxy к $ip не удался (см. A1 pods/proxy)"
  fi
done
res A10 "$a10" "${found:-запись для $SRC_POD.$SRC_NS не найдена ни у одного istiod}"

# ---------- итог ----------
log "Итог (сырые данные в $OUT)"
cat "$RESULTS"
