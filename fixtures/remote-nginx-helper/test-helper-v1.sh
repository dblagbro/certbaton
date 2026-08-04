#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "$(id -u)" != '0' ]]; then
  printf 'SKIP: test-helper-v1.sh requires a disposable Linux root environment.\n' >&2
  exit 77
fi

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SOURCE_HELPER="$SCRIPT_DIR/certbaton-helper-v1"
readonly TEST_ROOT="/var/lib/certbaton-helper-test.$$"
readonly TEST_SSH_USER='nobody'
readonly HELPER="$TEST_ROOT/certbaton-helper-v1"
readonly CONFIG_DIR="$TEST_ROOT/etc"
readonly CONFIG_PATH="$CONFIG_DIR/helper-v1.conf"
readonly LOCK_DIR="$TEST_ROOT/run"
readonly LOCK_PATH="$LOCK_DIR/helper-v1.lock"
readonly INCOMING_ROOT="$TEST_ROOT/incoming"
readonly RELEASE_ROOT="$TEST_ROOT/releases"
readonly BOOTSTRAP_TARGET="$TEST_ROOT/bootstrap"
readonly UPLOAD_ROOT="$TEST_ROOT/upload"
readonly SYSTEM_FIND="$(command -v find)"

PASS_COUNT=0

cleanup() {
  case "$TEST_ROOT" in
    /var/lib/certbaton-helper-test.[0-9]*) rm -rf -- "$TEST_ROOT" ;;
    *) printf 'Refusing to clean unexpected test root: %s\n' "$TEST_ROOT" >&2 ;;
  esac
}
trap cleanup EXIT

die() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf 'PASS: %s\n' "$1"
}

expect_success() {
  local expected_code="$1"
  shift
  local output
  if ! output="$("$HELPER" "$@" 2>&1)"; then
    printf '%s\n' "$output" >&2
    die "Expected success for: $*"
  fi
  [[ "$output" == *'"success":true'* && "$output" == *"\"code\":\"$expected_code\""* ]] || {
    printf '%s\n' "$output" >&2
    die "Success response did not contain code $expected_code"
  }
}

expect_failure() {
  local expected_code="$1"
  shift
  local output
  if output="$("$HELPER" "$@" 2>&1)"; then
    printf '%s\n' "$output" >&2
    die "Expected failure for: $*"
  fi
  [[ "$output" == *'"success":false'* && "$output" == *"\"code\":\"$expected_code\""* ]] || {
    printf '%s\n' "$output" >&2
    die "Failure response did not contain code $expected_code"
  }
}

expect_prepare_success() {
  local transaction_id="$1"
  local expected output
  expected="{\"version\":1,\"success\":true,\"code\":\"helper.prepared\",\"transactionId\":\"$transaction_id\",\"uploadPath\":\"$INCOMING_ROOT/$transaction_id\"}"
  output="$("$HELPER" prepare "$transaction_id" 2>&1)" || {
    printf '%s\n' "$output" >&2
    die "Expected prepare success for: $transaction_id"
  }
  [[ "$output" == "$expected" ]] || {
    printf 'Expected: %s\nActual:   %s\n' "$expected" "$output" >&2
    die 'Prepare did not return the exact canonical upload path.'
  }
}

expect_status() {
  local transaction_id="$1"
  local expected_status="$2"
  local expected_active="$3"
  local expected_recovery="$4"
  local output
  output="$("$HELPER" status "$transaction_id" 2>&1)" || {
    printf '%s\n' "$output" >&2
    die "Status failed for $transaction_id"
  }
  [[ "$output" == *"\"status\":\"$expected_status\""* ]] || die "Unexpected status for $transaction_id: $output"
  [[ "$output" == *"\"active\":$expected_active"* ]] || die "Unexpected active flag for $transaction_id: $output"
  [[ "$output" == *"\"recoveryRequired\":$expected_recovery"* ]] || die "Unexpected recovery flag for $transaction_id: $output"
}

upload_pair() {
  local transaction_id="$1"
  local private_key="${2:-$UPLOAD_ROOT/privkey.pem}"
  runuser -u "$TEST_SSH_USER" -- cp -- "$UPLOAD_ROOT/fullchain.pem" "$INCOMING_ROOT/$transaction_id/fullchain.pem"
  runuser -u "$TEST_SSH_USER" -- cp -- "$private_key" "$INCOMING_ROOT/$transaction_id/privkey.pem"
  runuser -u "$TEST_SSH_USER" -- chmod 0600 "$INCOMING_ROOT/$transaction_id/fullchain.pem" "$INCOMING_ROOT/$transaction_id/privkey.pem"
}

set_state() {
  local transaction_id="$1"
  local status="$2"
  local previous="$3"
  printf 'status=%s\nprevious=%s\n' "$status" "$previous" > "$RELEASE_ROOT/.state/$transaction_id.state"
  chown root:root -- "$RELEASE_ROOT/.state/$transaction_id.state"
  chmod 0600 -- "$RELEASE_ROOT/.state/$transaction_id.state"
}

force_current() {
  local target="$1"
  local temporary="$RELEASE_ROOT/.test-current.$$"
  rm -f -- "$temporary"
  ln -s -- "$target" "$temporary"
  mv -fT -- "$temporary" "$RELEASE_ROOT/current"
}

install -d -o root -g root -m 0755 -- "$TEST_ROOT"
install -d -o root -g root -m 0700 -- "$CONFIG_DIR" "$LOCK_DIR" "$BOOTSTRAP_TARGET" "$RELEASE_ROOT"
install -d -o root -g root -m 0755 -- "$TEST_ROOT/bin" "$UPLOAD_ROOT"

sed \
  -e "s|^PATH=.*|PATH='$TEST_ROOT/bin:/usr/sbin:/usr/bin:/sbin:/bin'|" \
  -e "s|^readonly CONFIG_DIR=.*|readonly CONFIG_DIR='$CONFIG_DIR'|" \
  -e "s|^readonly CONFIG_PATH=.*|readonly CONFIG_PATH='$CONFIG_PATH'|" \
  -e "s|^readonly LOCK_DIR=.*|readonly LOCK_DIR='$LOCK_DIR'|" \
  -e "s|^readonly LOCK_PATH=.*|readonly LOCK_PATH='$LOCK_PATH'|" \
  "$SOURCE_HELPER" > "$HELPER"
chmod 0755 -- "$HELPER"

printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -Eeuo pipefail' \
  "if [[ -e '$TEST_ROOT/fail-test-once' ]]; then" \
  "  rm -f -- '$TEST_ROOT/fail-test-once'" \
  '  exit 1' \
  'fi' \
  "printf 'test\\n' >> '$TEST_ROOT/nginx.log'" \
  > "$TEST_ROOT/bin/nginx"

printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -Eeuo pipefail' \
  "if [[ -e '$TEST_ROOT/fail-reload-once' ]]; then" \
  "  rm -f -- '$TEST_ROOT/fail-reload-once'" \
  '  exit 1' \
  'fi' \
  "printf 'reload\\n' >> '$TEST_ROOT/nginx.log'" \
  > "$TEST_ROOT/bin/systemctl"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -Eeuo pipefail' \
  "if [[ -e '$TEST_ROOT/fail-find-once' ]]; then" \
  "  rm -f -- '$TEST_ROOT/fail-find-once'" \
  '  exit 1' \
  'fi' \
  "exec '$SYSTEM_FIND' \"\$@\"" \
  > "$TEST_ROOT/bin/find"
chmod 0755 -- "$TEST_ROOT/bin/nginx" "$TEST_ROOT/bin/systemctl" "$TEST_ROOT/bin/find"

printf '%s\n' \
  "ssh_user=$TEST_SSH_USER" \
  "incoming_root=$INCOMING_ROOT" \
  "release_root=$RELEASE_ROOT" \
  "bootstrap_target=$BOOTSTRAP_TARGET" \
  'server_name=example.org' \
  'nginx_mode=host' \
  'nginx_container=-' \
  > "$CONFIG_PATH"
chown root:root -- "$CONFIG_PATH"
chmod 0600 -- "$CONFIG_PATH"
ln -s -- "$BOOTSTRAP_TARGET" "$RELEASE_ROOT/current"

openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -subj '/CN=example.org' -addext 'subjectAltName=DNS:example.org' \
  -keyout "$UPLOAD_ROOT/privkey.pem" -out "$UPLOAD_ROOT/fullchain.pem" >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$UPLOAD_ROOT/wrong-privkey.pem" >/dev/null 2>&1
chmod 0644 -- "$UPLOAD_ROOT/fullchain.pem" "$UPLOAD_ROOT/privkey.pem" "$UPLOAD_ROOT/wrong-privkey.pem"

readonly TX_COMMIT='00000000-0000-4000-8000-000000000001'
expect_prepare_success "$TX_COMMIT"
expect_prepare_success "$TX_COMMIT"
upload_pair "$TX_COMMIT"
expect_success 'helper.validated' validate "$TX_COMMIT"
[[ "$(stat -c '%u' -- "$INCOMING_ROOT/$TX_COMMIT")" == '0' ]] || die 'Validate did not freeze the incoming directory.'
expect_success 'helper.validated' validate "$TX_COMMIT"
expect_success 'helper.activated' activate "$TX_COMMIT"
expect_success 'helper.activated' activate "$TX_COMMIT"
expect_success 'helper.verified' verify "$TX_COMMIT"
expect_success 'helper.committed' commit "$TX_COMMIT"
[[ ! -e "$INCOMING_ROOT/$TX_COMMIT" && ! -L "$INCOMING_ROOT/$TX_COMMIT" ]] ||
  die 'Commit left incoming certificate material behind.'
expect_success 'helper.committed' commit "$TX_COMMIT"
expect_status "$TX_COMMIT" 'committed' 'true' 'false'
expect_failure 'helper.state_transition' rollback "$TX_COMMIT"
pass 'happy path and same-verb retries are idempotent'

readonly TX_COMMIT_RECOVERY='00000000-0000-4000-8000-000000000010'
expect_prepare_success "$TX_COMMIT_RECOVERY"
upload_pair "$TX_COMMIT_RECOVERY"
expect_success 'helper.validated' validate "$TX_COMMIT_RECOVERY"
commit_recovery_previous="$(readlink -- "$RELEASE_ROOT/current")"
expect_success 'helper.activated' activate "$TX_COMMIT_RECOVERY"
touch "$TEST_ROOT/fail-find-once"
expect_failure 'helper.incoming_cleanup' commit "$TX_COMMIT_RECOVERY"
expect_status "$TX_COMMIT_RECOVERY" 'active' 'true' 'false'
[[ -e "$INCOMING_ROOT/$TX_COMMIT_RECOVERY" ]] ||
  die 'The cleanup fault did not leave an incoming transaction to recover.'
expect_success 'helper.committed' commit "$TX_COMMIT_RECOVERY"
expect_status "$TX_COMMIT_RECOVERY" 'committed' 'true' 'false'
[[ ! -e "$INCOMING_ROOT/$TX_COMMIT_RECOVERY" && ! -L "$INCOMING_ROOT/$TX_COMMIT_RECOVERY" ]] ||
  die 'Retried commit left incoming certificate material behind.'
set_state "$TX_COMMIT_RECOVERY" 'active' "$commit_recovery_previous"
expect_status "$TX_COMMIT_RECOVERY" 'active' 'true' 'false'
expect_success 'helper.committed' commit "$TX_COMMIT_RECOVERY"
expect_status "$TX_COMMIT_RECOVERY" 'committed' 'true' 'false'
install -d -o root -g root -m 0700 -- "$INCOMING_ROOT/$TX_COMMIT_RECOVERY"
install -o root -g root -m 0600 -- "$UPLOAD_ROOT/privkey.pem" "$INCOMING_ROOT/$TX_COMMIT_RECOVERY/privkey.pem"
expect_success 'helper.committed' commit "$TX_COMMIT_RECOVERY"
[[ ! -e "$INCOMING_ROOT/$TX_COMMIT_RECOVERY" && ! -L "$INCOMING_ROOT/$TX_COMMIT_RECOVERY" ]] ||
  die 'A committed retry did not clean legacy incoming private-key material.'
pass 'commit cleanup failure, post-cleanup interruption, and legacy retry are safe'

readonly TX_ROLLBACK='00000000-0000-4000-8000-000000000002'
expect_prepare_success "$TX_ROLLBACK"
upload_pair "$TX_ROLLBACK"
expect_success 'helper.validated' validate "$TX_ROLLBACK"
expect_success 'helper.activated' activate "$TX_ROLLBACK"
expect_success 'helper.rolled_back' rollback "$TX_ROLLBACK"
expect_success 'helper.rolled_back' rollback "$TX_ROLLBACK"
expect_success 'helper.aborted' abort "$TX_ROLLBACK"
expect_success 'helper.aborted' abort "$TX_ROLLBACK"
expect_status "$TX_ROLLBACK" 'aborted' 'false' 'false'
pass 'rollback and abort retries preserve the prior generation'

readonly TX_ACTIVATE_FAIL='00000000-0000-4000-8000-000000000003'
expect_prepare_success "$TX_ACTIVATE_FAIL"
upload_pair "$TX_ACTIVATE_FAIL"
expect_success 'helper.validated' validate "$TX_ACTIVATE_FAIL"
touch "$TEST_ROOT/fail-test-once"
expect_failure 'helper.activation_failed' activate "$TX_ACTIVATE_FAIL"
expect_status "$TX_ACTIVATE_FAIL" 'validated' 'false' 'false'
expect_success 'helper.activated' activate "$TX_ACTIVATE_FAIL"
expect_success 'helper.rolled_back' rollback "$TX_ACTIVATE_FAIL"
expect_success 'helper.aborted' abort "$TX_ACTIVATE_FAIL"
pass 'failed activation restores the prior pointer and is retryable'

readonly TX_ROLLBACK_FAIL='00000000-0000-4000-8000-000000000004'
expect_prepare_success "$TX_ROLLBACK_FAIL"
upload_pair "$TX_ROLLBACK_FAIL"
expect_success 'helper.validated' validate "$TX_ROLLBACK_FAIL"
expect_success 'helper.activated' activate "$TX_ROLLBACK_FAIL"
touch "$TEST_ROOT/fail-reload-once"
expect_failure 'helper.rollback_reload' rollback "$TX_ROLLBACK_FAIL"
expect_status "$TX_ROLLBACK_FAIL" 'rolling-back' 'false' 'true'
expect_success 'helper.rolled_back' rollback "$TX_ROLLBACK_FAIL"
expect_success 'helper.aborted' abort "$TX_ROLLBACK_FAIL"
pass 'interrupted rollback records recovery-required state and resumes'

readonly TX_SYMLINK='00000000-0000-4000-8000-000000000005'
expect_prepare_success "$TX_SYMLINK"
runuser -u "$TEST_SSH_USER" -- ln -s -- /etc/passwd "$INCOMING_ROOT/$TX_SYMLINK/fullchain.pem"
runuser -u "$TEST_SSH_USER" -- cp -- "$UPLOAD_ROOT/privkey.pem" "$INCOMING_ROOT/$TX_SYMLINK/privkey.pem"
expect_failure 'helper.incoming_file' validate "$TX_SYMLINK"
expect_success 'helper.aborted' abort "$TX_SYMLINK"
pass 'SFTP symlink inputs are rejected without being followed'

readonly TX_EXTRA='00000000-0000-4000-8000-000000000006'
expect_prepare_success "$TX_EXTRA"
upload_pair "$TX_EXTRA"
runuser -u "$TEST_SSH_USER" -- touch "$INCOMING_ROOT/$TX_EXTRA/unexpected"
expect_failure 'helper.incoming_contents' validate "$TX_EXTRA"
expect_success 'helper.aborted' abort "$TX_EXTRA"
pass 'unexpected upload entries are rejected'

readonly TX_MISMATCH='00000000-0000-4000-8000-000000000007'
expect_prepare_success "$TX_MISMATCH"
upload_pair "$TX_MISMATCH" "$UPLOAD_ROOT/wrong-privkey.pem"
expect_failure 'helper.key_mismatch' validate "$TX_MISMATCH"
expect_success 'helper.aborted' abort "$TX_MISMATCH"
pass 'certificate and private-key mismatch is rejected'

readonly TX_STAGED_RECOVERY='00000000-0000-4000-8000-000000000008'
expect_prepare_success "$TX_STAGED_RECOVERY"
upload_pair "$TX_STAGED_RECOVERY"
install -d -o root -g root -m 0700 -- "$RELEASE_ROOT/$TX_STAGED_RECOVERY"
install -o root -g root -m 0644 -- "$UPLOAD_ROOT/fullchain.pem" "$RELEASE_ROOT/$TX_STAGED_RECOVERY/fullchain.pem"
install -o root -g root -m 0600 -- "$UPLOAD_ROOT/privkey.pem" "$RELEASE_ROOT/$TX_STAGED_RECOVERY/privkey.pem"
expect_success 'helper.validated' validate "$TX_STAGED_RECOVERY"
expect_success 'helper.activated' activate "$TX_STAGED_RECOVERY"
expect_success 'helper.rolled_back' rollback "$TX_STAGED_RECOVERY"
expect_success 'helper.aborted' abort "$TX_STAGED_RECOVERY"
pass 'validation resumes after a release move interrupted before state update'

readonly TX_ACTIVATING_RECOVERY='00000000-0000-4000-8000-000000000009'
expect_prepare_success "$TX_ACTIVATING_RECOVERY"
upload_pair "$TX_ACTIVATING_RECOVERY"
expect_success 'helper.validated' validate "$TX_ACTIVATING_RECOVERY"
previous_target="$(readlink -- "$RELEASE_ROOT/current")"
set_state "$TX_ACTIVATING_RECOVERY" 'activating' "$previous_target"
force_current "$RELEASE_ROOT/$TX_ACTIVATING_RECOVERY"
expect_status "$TX_ACTIVATING_RECOVERY" 'activating' 'true' 'true'
expect_success 'helper.activated' activate "$TX_ACTIVATING_RECOVERY"
expect_success 'helper.rolled_back' rollback "$TX_ACTIVATING_RECOVERY"
expect_success 'helper.aborted' abort "$TX_ACTIVATING_RECOVERY"
pass 'activation resumes from write-ahead state after an interruption'

expect_failure 'helper.transaction_id' status 'NOT-A-UUID'
cp -- "$CONFIG_PATH" "$CONFIG_PATH.saved"
sed "s|^release_root=.*|release_root=$INCOMING_ROOT/nested|" "$CONFIG_PATH.saved" > "$CONFIG_PATH"
chmod 0600 -- "$CONFIG_PATH"
expect_failure 'helper.config_overlap' status "$TX_COMMIT"
mv -f -- "$CONFIG_PATH.saved" "$CONFIG_PATH"
pass 'invalid identifiers and overlapping managed roots are rejected'

printf 'All %d helper fixture groups passed.\n' "$PASS_COUNT"
