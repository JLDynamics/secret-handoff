#!/usr/bin/env bash
# Proves the agent-facing output never contains the secret value.
# Run: bash scripts/selftest.sh
set -uo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRET="$SKILL_DIR/agent-secret.js"
run() { node "$SECRET" "$@"; }

export AGENT_SECRETS_DIR="$(mktemp -d)"
CANARY="CANARY-$$-DONOTLEAK"
LOG="$(mktemp)"
fail=0

check() { # name, condition
  if [ "$2" -eq 0 ]; then printf '  ok   %s\n' "$1"; else printf '  FAIL %s\n' "$1"; fail=1; fi
}

echo "state: $AGENT_SECRETS_DIR"

ID="$(run ask --name "Self test key" --for "prove the handoff works" --json \
  | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).id))')"
check "ask creates a request" $?

printf '%s\n' "$CANARY" | run fill "$ID" >>"$LOG" 2>&1
check "fill accepts a value" $?

[ "$(run status "$ID" | awk '/^status:/{print $2}')" = "ready" ]
check "status becomes ready" $?

[ "$(stat -f '%OLp' "$AGENT_SECRETS_DIR/store/$ID")" = "600" ]
check "stored value is 0600" $?

[ "$(stat -f '%OLp' "$AGENT_SECRETS_DIR")" = "700" ]
check "state directory is 0700" $?

! grep -q "$CANARY" "$AGENT_SECRETS_DIR/requests/$ID.json"
check "request metadata holds no value" $?

PATHOUT="$(run path "$ID")"
[ "$(stat -f '%OLp' "$PATHOUT")" = "600" ]
check "path mode returns a 0600 file" $?

run exec "$ID" --env K -- sh -c 'test -n "$K"' >/dev/null 2>&1
check "exec runs the command with the value" $?

run exec "$ID" --env K -- sh -c 'exit 3' >/dev/null 2>&1
[ $? -eq 3 ]
check "exec propagates exit codes" $?

run revoke "$ID" >/dev/null 2>&1
[ ! -f "$AGENT_SECRETS_DIR/store/$ID" ]
check "revoke destroys the value" $?

# The important one: everything the agent would have seen.
run list >"$LOG" 2>&1
run status "$ID" >>"$LOG" 2>&1
if grep -q "$CANARY" "$LOG"; then
  echo "  FAIL agent-visible output contained the secret"
  fail=1
else
  echo "  ok   agent-visible output never contains the secret"
fi

rm -rf "$AGENT_SECRETS_DIR" "$LOG"
[ "$fail" -eq 0 ] && echo "all checks passed" || echo "FAILURES"
exit "$fail"
