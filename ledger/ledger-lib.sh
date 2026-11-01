#!/usr/bin/env bash
# DRAFT v1 (never run against GitHub). STUB ledger writer for the M1 REHEARSAL only: it proves GitHub branch protection and
# compare-and-swap behaviour, NOT Owner-signature verification (the real writer must verify Owner signatures before appending).
# Only git is used (no GitHub API), so the same code is self-testable against a local bare repository.
# Layout on branch ledger/claims (one linear chain; claims AND revocations share it so a revocation and a claim are
# serialised by the same fast-forward compare-and-swap):
#   chain.log           seq|type|key|mission|digest|who|prev|hash     (type: claim | revoke | complete)
#   claims/<key>.json   existence marker for a claim (key = sha256(nonce))
# Branch ledger/orders holds acts/<key> (the rehearsal "action" marker, created at most once).
# A push is NEVER forced. A non-fast-forward rejection is the arbiter between racing writers.
# Safety guard (review item 6/8): the library only talks to the disposable rehearsal repository, or to a local temp bare repository
# when L_LOCAL_TEST=1 (self-test). Anything else is refused before any git command runs.
: "${LEDGER_REMOTE:?}"
L_ALLOWED_REMOTE="https://github.com/telesty-tpicc/rehearsal-tpicc-target.git"
if [ "${L_LOCAL_TEST:-}" = 1 ]; then case "$LEDGER_REMOTE" in /tmp/*|/var/folders/*|/private/var/folders/*|/private/tmp/*) ;; *) echo "REFUSED: local test remote must be under a temp directory" >&2; exit 2;; esac
else [ "$LEDGER_REMOTE" = "$L_ALLOWED_REMOTE" ] || { echo "REFUSED: remote must be exactly $L_ALLOWED_REMOTE" >&2; exit 2; }; fi
l_field_ok() { printf '%s' "$1" | grep -Eq '^[A-Za-z0-9._:-]{1,128}$'; }
l_safe_dir() { case "$1" in /tmp/*|/var/folders/*|/private/var/folders/*|/private/tmp/*|"${RUNNER_TEMP:-/nonexistent}"/*) return 0;; *) echo "REFUSED: working directory outside a temp directory: $1" >&2; return 1;; esac; }
L_CLAIMS=${L_CLAIMS:-ledger/claims}; L_ORDERS=${L_ORDERS:-ledger/orders}
L_ZERO=$(printf '0%.0s' $(seq 1 64))
l_git() { git -c credential.helper= -c 'credential.helper=!f() { echo username=x-access-token; echo "password=${L_TOKEN:-x}"; }; f' "$@"; }
l_sha() { shasum -a 256 | cut -d' ' -f1; }
l_hash() { printf '%s' "$1" | l_sha; }
# l_clone DIR BRANCH
l_clone() { l_safe_dir "$1" || return 1; rm -rf "$1"; l_git clone -q --single-branch --branch "$2" "$LEDGER_REMOTE" "$1" 2>/dev/null || return 1
  git -C "$1" config user.email ledger-writer@example.invalid; git -C "$1" config user.name ledger-writer; }
l_sync() { l_git -C "$1" fetch -q origin "$2" 2>/dev/null && git -C "$1" reset -q --hard FETCH_HEAD; }
l_push_class() { # stdin: push output -> RULE | RACE | OTHER
  local o; o=$(cat); if printf '%s' "$o" | grep -Eiq 'GH013|rule violation|protected branch|not permitted|permission|403'; then echo RULE
  elif printf '%s' "$o" | grep -Eiq 'non-fast-forward|fetch first|stale info|failed to update ref|cannot lock ref'; then echo RACE; else echo OTHER; fi; }
# l_append DIR TYPE KEY MISSION DIGEST WHO  -> prints OUTCOME, returns 0 ok | 10 replay | 11 revoked | 12 conflict | 13 no-claim | 20 push/fetch failed | 21 refused by rule
l_append() {
  local d=$1 type=$2 key=$3 mission=$4 digest=$5 who=$6 tries=0 rec seq prev hash line out cls
  l_safe_dir "$d" || return 22
  for f in "$type" "$key" "$mission" "$digest" "$who"; do l_field_ok "$f" || { echo BAD_FIELD; return 22; }; done
  case $type in claim|revoke|complete) ;; *) echo BAD_TYPE; return 22;; esac
  { [ "$type" != claim ] && [ "$type" != complete ]; } || printf "%s" "$key" | grep -Eq "^[0-9a-f]{64}$" || { echo BAD_KEY; return 22; }
  while [ $tries -lt "${L_RETRIES:-15}" ]; do
    tries=$((tries+1))
    l_sync "$d" "$L_CLAIMS" || { echo FETCH_FAILED; return 20; }
    touch "$d/chain.log"
    case $type in
      claim)
        awk -F'|' -v m="$mission" '$2=="revoke"&&$3==m{f=1}END{exit f?0:1}' "$d/chain.log" && { echo REVOKED; return 11; }
        rec=$(awk -F'|' -v k="$key" '$2=="claim"&&$3==k{print $5"|"$6}' "$d/chain.log")
        if [ -n "$rec" ]; then
          [ "${rec%%|*}" = "$digest" ] || { echo CONFLICT; return 12; }
          [ "${rec#*|}" = "$who" ] && { echo IDEMPOTENT; return 0; }
          echo REPLAY; return 10
        fi;;
      revoke) awk -F'|' -v m="$key" '$2=="revoke"&&$3==m{f=1}END{exit f?0:1}' "$d/chain.log" && { echo IDEMPOTENT; return 0; };;
      complete)
        awk -F'|' -v k="$key" '$2=="claim"&&$3==k{f=1}END{exit f?0:1}' "$d/chain.log" || { echo NO_CLAIM; return 13; }
        awk -F'|' -v k="$key" '$2=="complete"&&$3==k{f=1}END{exit f?0:1}' "$d/chain.log" && { echo IDEMPOTENT; return 0; };;
    esac
    seq=$(( $(wc -l < "$d/chain.log") + 1 ))
    prev=$(tail -n 1 "$d/chain.log" | awk -F'|' '{print $8}'); prev=${prev:-$L_ZERO}
    hash=$(l_hash "$prev|$seq|$type|$key|$mission|$digest|$who")
    line="$seq|$type|$key|$mission|$digest|$who|$prev|$hash"
    printf '%s\n' "$line" >> "$d/chain.log"
    [ "$type" = claim ] && { mkdir -p "$d/claims"; printf '%s\n' "$line" > "$d/claims/$key.json"; }
    git -C "$d" add -A && git -C "$d" commit -qm "ledger: $type $key"
    out=$(l_git -C "$d" push -q origin "HEAD:refs/heads/$L_CLAIMS" 2>&1 </dev/null) && { echo APPENDED; return 0; }
    cls=$(printf '%s' "$out" | l_push_class)
    [ "$cls" = RULE ] && { echo REFUSED_BY_RULE; return 21; }
    [ "$cls" = RACE ] || { echo "PUSH_FAILED"; return 20; }
  done
  echo RETRIES_EXHAUSTED; return 20
}
# l_act ORDERSDIR KEY CLAIMSDIR : create acts/KEY on ledger/orders at most once, ONLY if the claims chain holds a claim for KEY whose mission
# is not revoked (checked on a freshly fetched chain). prints ACTED | ALREADY | NO_CLAIM | REVOKED.
# Residual (cross-branch): a revocation committed between this check and the push cannot be excluded by GitHub; see review finding R-2.
l_act() {
  local d=$1 key=$2 cd=$3 tries=0 out cls mission
  l_safe_dir "$d" || return 22; printf "%s" "$key" | grep -Eq "^[0-9a-f]{64}$" || { echo BAD_KEY; return 22; }
  l_sync "$cd" "$L_CLAIMS" || { echo FETCH_FAILED; return 20; }
  mission=$(awk -F'|' -v k="$key" '$2=="claim"&&$3==k{print $4}' "$cd/chain.log")
  [ -n "$mission" ] || { echo NO_CLAIM; return 13; }
  awk -F'|' -v m="$mission" '$2=="revoke"&&$3==m{f=1}END{exit f?0:1}' "$cd/chain.log" && { echo REVOKED; return 11; }
  while [ $tries -lt "${L_RETRIES:-15}" ]; do
    tries=$((tries+1)); l_sync "$d" "$L_ORDERS" || { echo FETCH_FAILED; return 20; }
    [ -e "$d/acts/$key" ] && { echo ALREADY; return 0; }
    mkdir -p "$d/acts"; echo "acted $key" > "$d/acts/$key"; git -C "$d" add -A && git -C "$d" commit -qm "act $key"
    out=$(l_git -C "$d" push -q origin "HEAD:refs/heads/$L_ORDERS" 2>&1 </dev/null) && { echo ACTED; return 0; }
    cls=$(printf '%s' "$out" | l_push_class); [ "$cls" = RULE ] && { echo REFUSED_BY_RULE; return 21; }; [ "$cls" = RACE ] || { echo PUSH_FAILED; return 20; }
  done; echo RETRIES_EXHAUSTED; return 20
}
# l_reconcile CLAIMSDIR ORDERSDIR : every claim without a complete gets its action (once) and a complete entry
l_reconcile() {
  local cd=$1 od=$2 key who n=0; l_sync "$cd" "$L_CLAIMS" || return 20
  for key in $(awk -F'|' '$2=="claim"{c[$3]=1}$2=="complete"{delete c[$3]}END{for(k in c)print k}' "$cd/chain.log"); do
    who=$(awk -F'|' -v k="$key" '$2=="claim"&&$3==k{print $6}' "$cd/chain.log")
    l_act "$od" "$key" "$cd" >/dev/null; l_append "$cd" complete "$key" "-" "-" "reconcile" >/dev/null; n=$((n+1))
  done; echo "RECONCILED $n"
}
# l_verify DIR : recompute the whole hash chain in bash (chain content is never given to a shell or awk system()). prints OK <count> | BAD <seq>
l_verify() {
  l_sync "$1" "$L_CLAIMS" || { echo FETCH_FAILED; return 20; }
  local p=$L_ZERO n=0 seq type key mission digest who prev hash extra
  while IFS='|' read -r seq type key mission digest who prev hash extra; do
    n=$((n+1)); [ -z "$extra" ] && [ "$seq" = "$n" ] && [ "$prev" = "$p" ] || { echo "BAD $n"; return 1; }
    [ "$(l_hash "$prev|$seq|$type|$key|$mission|$digest|$who")" = "$hash" ] || { echo "BAD $n"; return 1; }
    p=$hash
  done < "$1/chain.log"; echo "OK $n"
}
# l_checkpoint_ok DIR TIPSHA : the current tip must be a descendant of an Owner-recorded checkpoint SHA
l_checkpoint_ok() { git -C "$1" cat-file -e "$2^{commit}" 2>/dev/null && git -C "$1" merge-base --is-ancestor "$2" HEAD && echo OK || echo CHECKPOINT_MISMATCH; }
