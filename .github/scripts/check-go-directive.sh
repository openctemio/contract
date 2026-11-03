#!/usr/bin/env bash
# Every module's go directive is the minimum its code and dependencies need,
# and never newer than the oldest Go the consumers build with (the sensor
# SDK, the platform API, the sensor). Raising CONSUMER_GO_FLOOR needs every
# consumer on that Go first.
set -euo pipefail
CONSUMER_GO_FLOOR="1.26.0"

ver() { printf '%s\n' "$1" | awk -F. '{ printf "%d%04d%04d\n", $1, $2, ($3 == "" ? 0 : $3) }'; }

status=0
while IFS= read -r mod; do
  go_line=$(awk '$1 == "go" { print $2; exit }' "$mod")
  if [ -z "$go_line" ]; then
    echo "ERROR: $mod has no go directive"; status=1; continue
  fi
  if [ "$(ver "$go_line")" -gt "$(ver "$CONSUMER_GO_FLOOR")" ]; then
    echo "ERROR: $mod declares go $go_line, newer than the consumer floor $CONSUMER_GO_FLOOR"
    status=1
  else
    echo "ok: $mod go $go_line"
  fi
done < <(git ls-files '*go.mod' 'go.mod')
exit $status
