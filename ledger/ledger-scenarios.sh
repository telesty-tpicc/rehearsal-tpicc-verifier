#!/usr/bin/env bash
# DRAFT v1 (never run against GitHub). Self-asserting ledger scenarios L5-L16. Used two ways, with identical code:
#   local self-test (ledger-selftest.sh): LEDGER_REMOTE = a local bare repository (logic only, no GitHub rules);
#   GitHub rehearsal (workflow ledger-tests.yml): LEDGER_REMOTE = the rehearsal target repository, token = verifier App token.
# usage: LEDGER_REMOTE=... [L_TOKEN=...] [RUN=<unique>] ./ledger-scenarios.sh SCENARIO...
# Stop rule: the first FAIL exits non-zero and stops the run (same as M1a).
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd); . "$HERE/ledger-lib.sh"
RUN=${RUN:-$(date +%s)}; T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
pass() { echo "PASS $1 $2"; }; die() { echo "FAIL $1 $2"; exit 3; }
dir() { l_clone "$T/$1" "${2:-$L_CLAIMS}" || die setup "cannot clone $L_CLAIMS"; echo "$T/$1"; }
nth() { grep -c "$2" "$1" 2>/dev/null || true; }

sc_L6() { # 20 parallel claims of one nonce: exactly one wins, the others are replays
  local n="n6-$RUN" key i; key=$(l_hash "$n")
  for i in $(seq 1 20); do ( d=$(dir "p6-$i"); l_append "$d" claim "$key" "m6-$RUN" "dig-6" "w$i" > "$T/o6-$i" ) & done; wait
  local won=$(cat "$T"/o6-* | grep -c '^APPENDED$') rep=$(cat "$T"/o6-* | grep -c '^REPLAY$')
  [ "$won" = 1 ] && [ "$rep" = 19 ] || die L6 "winners=$won replays=$rep (outcomes: $(cat "$T"/o6-* | sort | uniq -c | tr '\n' ' '))"
  local d; d=$(dir v6); [ "$(awk -F'|' -v k="$key" '$2=="claim"&&$3==k' "$d/chain.log" | wc -l | tr -d ' ')" = 1 ] || die L6 "more than one claim line"
  pass L6 "exactly one claim, 19 replays"; }
sc_L7() { local n="n7-$RUN" key d; key=$(l_hash "$n"); d=$(dir d7)
  [ "$(l_append "$d" claim "$key" "m7-$RUN" dig-7 first)" = APPENDED ] || die L7 "first claim failed"
  [ "$(l_append "$d" claim "$key" "m7-$RUN" dig-7 second)" = REPLAY ] || die L7 "replay accepted"; pass L7 "replay rejected"; }
sc_L8() { # 50 trials: a revocation racing a claim for the same mission; no claim may follow the revocation
  local t d bad=0 key
  for t in $(seq 1 50); do key=$(l_hash "n8-$t-$RUN")
    ( d=$(dir "rv8-$t"); l_append "$d" revoke "m8-$t-$RUN" "m8-$t-$RUN" - owner > /dev/null ) &
    ( d=$(dir "cl8-$t"); l_append "$d" claim "$key" "m8-$t-$RUN" dig-8 w > /dev/null ) &
    wait; done
  d=$(dir v8); bad=$(awk -F'|' -v r="$RUN" '$4 ~ ("-" r "$") && $2=="revoke"{rv[$4]=$1}$4 ~ ("-" r "$") && $2=="claim"{cl[$4]=$1}END{for(m in rv)if(m in cl&&cl[m]>rv[m])b++;print b+0}' "$d/chain.log")
  [ "$bad" = 0 ] || die L8 "$bad claim(s) landed after a revocation"; pass L8 "50 trials, no claim after revocation"; }
sc_L9() { # crash after the claim, before the action: reconcile completes it exactly once
  local n="n9-$RUN" key d od; key=$(l_hash "$n"); d=$(dir c9); od=$(dir o9 "$L_ORDERS")
  [ "$(l_append "$d" claim "$key" "m9-$RUN" dig-9 w)" = APPENDED ] || die L9 "claim failed"
  l_reconcile "$d" "$od" >/dev/null; l_reconcile "$d" "$od" >/dev/null; l_sync "$od" "$L_ORDERS"; l_sync "$d" "$L_CLAIMS"
  [ -e "$od/acts/$key" ] || die L9 "action never happened"
  [ "$(awk -F'|' -v k="$key" '$2=="complete"&&$3==k' "$d/chain.log" | wc -l | tr -d ' ')" = 1 ] || die L9 "complete entry count is not 1"
  [ "$(git -C "$od" log --oneline -- "acts/$key" | wc -l | tr -d ' ')" = 1 ] || die L9 "action committed more than once"
  pass L9 "action once, complete once"; }
sc_L10() { # crash before the claim push: nothing consumed, retry succeeds
  local n="n10-$RUN" key d before after; key=$(l_hash "$n"); d=$(dir c10); before=$(git -C "$d" rev-parse HEAD)
  echo junk >> "$d/chain.log"; git -C "$d" add -A; git -C "$d" commit -qm "abandoned, never pushed"; rm -rf "$d"; d=$(dir c10b)
  [ "$(git -C "$d" rev-parse HEAD)" = "$(l_git ls-remote "$LEDGER_REMOTE" "refs/heads/$L_CLAIMS" | cut -f1)" ] || die L10 "remote moved by an unpushed commit"
  [ "$(l_append "$d" claim "$key" "m10-$RUN" dig-10 w)" = APPENDED ] || die L10 "retry failed"; pass L10 "unpushed claim consumed nothing; retry ok"; }
sc_L11() { local n="n11-$RUN" key d; key=$(l_hash "$n"); d=$(dir d11)
  [ "$(l_append "$d" claim "$key" "m11-$RUN" dig-11 w)" = APPENDED ] || die L11 "first"
  [ "$(l_append "$d" claim "$key" "m11-$RUN" dig-11 w)" = IDEMPOTENT ] || die L11 "retry not idempotent"
  [ "$(awk -F'|' -v k="$key" '$2=="claim"&&$3==k' "$d/chain.log" | wc -l | tr -d ' ')" = 1 ] || die L11 "duplicate entry"; pass L11 "idempotent"; }
sc_L12() { local n="n12-$RUN" key d; key=$(l_hash "$n"); d=$(dir d12)
  [ "$(l_append "$d" claim "$key" "m12-$RUN" dig-A w)" = APPENDED ] || die L12 "first"
  [ "$(l_append "$d" claim "$key" "m12-$RUN" dig-B w)" = CONFLICT ] || die L12 "digest conflict accepted"; pass L12 "conflict rejected"; }
sc_chain() { local d; d=$(dir dv); local r; r=$(l_verify "$d"); case $r in "OK "*) pass chain "$r";; *) die chain "$r";; esac; }
sc_L5check() { # after attacks: an agent-forged claim in refs/ledger/* must not consume the real nonce
  local key d; key=$(l_hash "L5-FORGED-NONCE"); d=$(dir d5)
  [ "$(l_append "$d" claim "$key" "m5" dig-5 w)" = APPENDED ] || die L5 "forged ref consumed or blocked the nonce"; pass L5 "forged refs/ledger entry conferred nothing"; }
sc_L13_local() { # LOCAL ONLY (needs a remote without rules): tamper with history; chain and checkpoint audits must detect it
  [ "${L_LOCAL_TEST:-}" = 1 ] || die L13_local "refused: local self-test only (the GitHub L13 is an Owner-run break-glass step)"
  local d cp r; d=$(dir d13); cp=$(git -C "$d" rev-parse HEAD)
  sed -i.bak '1s/|claim|/|claim |/' "$d/chain.log" 2>/dev/null; rm -f "$d/chain.log.bak"; git -C "$d" commit -qam "tamper"; git -C "$d" push -q -f origin "HEAD:refs/heads/$L_CLAIMS" >/dev/null 2>&1
  d=$(dir d13b); r=$(l_verify "$d"); case $r in BAD*) ;; *) die L13 "tamper not detected by chain: $r";; esac
  git -C "$d" reset -q --hard "$cp~1" 2>/dev/null; [ "$(l_checkpoint_ok "$d" "$cp")" = CHECKPOINT_MISMATCH ] || die L13 "rewind below checkpoint not detected"
  pass L13_local "tamper and rollback detected"; }
sc_L16() { # GITHUB ONLY, DESTRUCTIVE if RL1 is misconfigured: the writer App must not be able to force-push or delete a ledger branch
  [ "${L16_CONFIRM:-}" = "I CONFIRM L16 NOW" ] || die L16 "refused: needs the Owner's separate confirmation immediately before this test"
  [ "${L_LOCAL_TEST:-}" != 1 ] || die L16 "GitHub only"
  local d out; d=$(dir d16); git -C "$d" commit -q --allow-empty --amend -m "rewrite attempt"
  out=$(l_git -C "$d" push -q -f origin "HEAD:refs/heads/$L_CLAIMS" 2>&1 </dev/null) && die L16 "FORCE PUSH ACCEPTED"
  printf '%s' "$out" | grep -Eiq 'GH013|rule violation|protected|not permitted|403' || die L16 "force push refused without a rule message (inconclusive): $(printf '%s' "$out" | tail -n 2)"
  out=$(l_git -C "$d" push -q origin ":refs/heads/$L_ORDERS" 2>&1 </dev/null) && die L16 "DELETE ACCEPTED (recreate $L_ORDERS from the Owner clone)"
  printf '%s' "$out" | grep -Eiq 'GH013|rule violation|protected|not permitted|403' || die L16 "delete refused without a rule message (inconclusive)"
  pass L16 "writer cannot force-push or delete"; }
sc_L18() { # order publication cannot bypass a claim: no claim -> no act; revoked -> no act; valid claim -> act once
  local key d od cd; key=$(l_hash "n18-$RUN"); cd=$(dir c18); od=$(dir o18 "$L_ORDERS")
  [ "$(l_act "$od" "$key" "$cd")" = NO_CLAIM ] || die L18 "act without a claim was not refused"
  l_sync "$od" "$L_ORDERS"; [ ! -e "$od/acts/$key" ] || die L18 "act marker exists without a claim"
  [ "$(l_append "$cd" claim "$key" "m18-$RUN" dig-18 w)" = APPENDED ] || die L18 "claim"
  [ "$(l_append "$cd" revoke "m18-$RUN" "m18-$RUN" - owner)" = APPENDED ] || die L18 "revoke"
  [ "$(l_act "$od" "$key" "$cd")" = REVOKED ] || die L18 "act after revocation was not refused"
  local k2; k2=$(l_hash "n18b-$RUN"); l_append "$cd" claim "$k2" "m18b-$RUN" dig-18 w >/dev/null
  [ "$(l_act "$od" "$k2" "$cd")" = ACTED ] || die L18 "valid claim could not act"; [ "$(l_act "$od" "$k2" "$cd")" = ALREADY ] || die L18 "act not once"
  pass L18 "no act without a valid claim"; }
sc_L19() { # sequential: a claim after a committed revocation fails closed
  local key d; key=$(l_hash "n19-$RUN"); d=$(dir d19)
  [ "$(l_append "$d" revoke "m19-$RUN" "m19-$RUN" - owner)" = APPENDED ] || die L19 "revoke"
  [ "$(l_append "$d" claim "$key" "m19-$RUN" dig-19 w)" = REVOKED ] || die L19 "claim after revocation accepted"
  l_sync "$d" "$L_CLAIMS"; [ ! -e "$d/claims/$key.json" ] || die L19 "claim marker exists"; pass L19 "claim after revocation refused"; }
sc_L20() { # stale writer: a commit built on an old tip is rejected by the server (compare-and-swap), nothing is overwritten
  local k1 k2 old new tip1 tip2; k1=$(l_hash "n20a-$RUN"); k2=$(l_hash "n20b-$RUN"); old=$(dir s20a); new=$(dir s20b)
  l_sync "$old" "$L_CLAIMS"; [ "$(l_append "$new" claim "$k1" "m20a-$RUN" dig-20 w)" = APPENDED ] || die L20 "setup claim"
  tip1=$(l_git ls-remote "$LEDGER_REMOTE" "refs/heads/$L_CLAIMS" | cut -f1)
  echo "stale|claim|$k2" >> "$old/chain.log"; git -C "$old" add -A; git -C "$old" commit -qm stale
  l_git -C "$old" push -q origin "HEAD:refs/heads/$L_CLAIMS" >/dev/null 2>&1 </dev/null && die L20 "STALE PUSH ACCEPTED"
  tip2=$(l_git ls-remote "$LEDGER_REMOTE" "refs/heads/$L_CLAIMS" | cut -f1); [ "$tip1" = "$tip2" ] || die L20 "tip moved after a rejected stale push"
  pass L20 "stale push rejected, tip unchanged"; }
sc_L21() { local d; d=$(dir d21); local o; o=$(l_append "$d" claim "$(l_hash x)" "m|bad" dig w); [ "$o" = BAD_FIELD ] || die L21 "unsafe field accepted: $o"
  o=$(l_append "$d" claim "not-hex" "m21" dig w); [ "$o" = BAD_KEY ] || die L21 "non-hex claim key accepted: $o"; pass L21 "malformed input refused"; }
sc_L22_local() { # unreachable remote: every operation fails closed, nothing acted
  [ "${L_LOCAL_TEST:-}" = 1 ] || die L22 "local only"
  local d key o rc; d=$(dir d22); key=$(l_hash "n22-$RUN"); git -C "$d" remote set-url origin "$T/does-not-exist.git"
  o=$(l_append "$d" claim "$key" "m22-$RUN" dig w); rc=$?
  [ "$o" = FETCH_FAILED ] && [ $rc -eq 20 ] || die L22 "did not fail closed: $o rc=$rc"; pass L22_local "unreachable remote fails closed"; }
sc_L23_local() { # LOCAL ONLY: a REAL rule refusal (tip unchanged) must still be refused, not retried forever or turned into success
  [ "${L_LOCAL_TEST:-}" = 1 ] || die L23 "local only"
  local d key o rc h="$LEDGER_REMOTE/hooks/update"; key=$(l_hash "n23-$RUN"); d=$(dir d23)
  cp "$h" "$h.keep" 2>/dev/null; printf '#!/bin/sh\necho "remote: error: GH013: Repository rule violations found" >&2\necho "remote: - Cannot update this protected ref." >&2\nexit 1\n' > "$h"; chmod +x "$h"
  o=$(L_RETRIES=4 l_append "$d" claim "$key" "m23-$RUN" dig-23 w); rc=$?
  if [ -f "$h.keep" ]; then mv "$h.keep" "$h"; else rm -f "$h"; fi
  [ "$o" = REFUSED_BY_RULE ] && [ $rc -eq 21 ] || die L23 "real rule refusal not reported as refused: $o rc=$rc"
  l_sync "$d" "$L_CLAIMS"; [ ! -e "$d/claims/$key.json" ] || die L23 "claim landed despite the refusal"; pass L23_local "real rule refusal still refused"; }
sc_all_local() { sc_L6; sc_L7; sc_L8; sc_L9; sc_L10; sc_L11; sc_L12; sc_L18; sc_L19; sc_L20; sc_L21; sc_L22_local; sc_L23_local; sc_chain; sc_L13_local; }
# L16 is deliberately NOT part of all_github: it is run alone, after the Owner's separate confirmation.
sc_all_github() { sc_L6; sc_L7; sc_L8; sc_L9; sc_L10; sc_L11; sc_L12; sc_L18; sc_L19; sc_L20; sc_L21; sc_chain; sc_L5check; }
for s in "$@"; do declare -F "sc_$s" >/dev/null || { echo "unknown scenario $s"; exit 2; }; "sc_$s"; done
