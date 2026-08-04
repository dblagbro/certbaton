#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

readonly state_root=/fixture-state
readonly public_key_input=/fixture-input/ssh/fixture_ed25519.pub
readonly public_output=/fixture-output/pki
readonly fixture_hostname="${CERTBATON_FIXTURE_HOSTNAME:-certbaton-fixture.test}"

fail() {
    printf 'fixture initialization failed: %s\n' "$*" >&2
    exit 1
}

require_regular_file() {
    local path="$1"
    [[ -f "$path" && ! -L "$path" ]] || fail "required regular file is missing: $path"
}

generate_leaf() {
    local destination="$1"
    local serial="$2"
    local label="$3"
    local request="$destination/request.csr"
    local extensions="$destination/extensions.cnf"

    mkdir -p "$destination"
    openssl genrsa -out "$destination/privkey.pem" 2048 >/dev/null 2>&1
    openssl req \
        -new \
        -sha256 \
        -key "$destination/privkey.pem" \
        -subj "/CN=${fixture_hostname}/O=CertBaton Local Fixture/OU=${label}" \
        -out "$request"
    cat >"$extensions" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${fixture_hostname},DNS:localhost,IP:127.0.0.1
EOF
    openssl x509 \
        -req \
        -sha256 \
        -in "$request" \
        -CA "$state_root/ca/ca.crt" \
        -CAkey "$state_root/ca/ca.key" \
        -set_serial "$serial" \
        -days 14 \
        -extfile "$extensions" \
        -out "$destination/cert.pem"
    cat "$destination/cert.pem" "$state_root/ca/ca.crt" >"$destination/fullchain.pem"
    rm -f "$request" "$extensions"
    chmod 0600 "$destination/privkey.pem"
    chmod 0644 "$destination/cert.pem" "$destination/fullchain.pem"
}

mkdir -p \
    "$state_root/ca" \
    "$state_root/inject/nginx" \
    "$state_root/ssh" \
    "$state_root/tls/active" \
    "$state_root/tls/backup" \
    "$state_root/tls/baseline" \
    "$state_root/tls/candidate" \
    "$state_root/tls/staging" \
    "$state_root/webroot/.well-known/acme-challenge" \
    "$public_output" \
    /run/nginx \
    /run/sshd \
    /var/lib/nginx/tmp/client \
    /var/lib/nginx/tmp/fastcgi \
    /var/lib/nginx/tmp/proxy \
    /var/lib/nginx/tmp/scgi \
    /var/lib/nginx/tmp/uwsgi

require_regular_file "$public_key_input"
if [[ "$(grep -Evc '^[[:space:]]*(#|$)' "$public_key_input")" -ne 1 ]] ||
   ! grep -Eq '^ssh-ed25519[[:space:]][A-Za-z0-9+/=]+([[:space:]].*)?$' "$public_key_input"; then
    fail "the runtime key input must contain exactly one Ed25519 public key"
fi

install -o root -g root -m 0644 \
    "$public_key_input" \
    "$state_root/ssh/authorized_keys"

if [[ ! -f "$state_root/ssh/ssh_host_ed25519_key" ]]; then
    ssh-keygen \
        -q \
        -t ed25519 \
        -N '' \
        -C certbaton-local-fixture-host \
        -f "$state_root/ssh/ssh_host_ed25519_key"
fi
require_regular_file "$state_root/ssh/ssh_host_ed25519_key"
require_regular_file "$state_root/ssh/ssh_host_ed25519_key.pub"
chown root:root "$state_root/ssh/ssh_host_ed25519_key" "$state_root/ssh/ssh_host_ed25519_key.pub"
chmod 0600 "$state_root/ssh/ssh_host_ed25519_key"
chmod 0644 "$state_root/ssh/ssh_host_ed25519_key.pub"

if [[ ! -f "$state_root/.initialized" ]]; then
    openssl genrsa -out "$state_root/ca/ca.key" 2048 >/dev/null 2>&1
    openssl req \
        -x509 \
        -new \
        -sha256 \
        -key "$state_root/ca/ca.key" \
        -days 30 \
        -subj '/CN=CertBaton Local Fixture CA/O=CertBaton Local Fixture' \
        -out "$state_root/ca/ca.crt"

    generate_leaf "$state_root/tls/baseline" 1001 baseline
    generate_leaf "$state_root/tls/candidate" 1002 candidate

    install -o root -g root -m 0644 \
        "$state_root/tls/baseline/fullchain.pem" \
        "$state_root/tls/active/fullchain.pem"
    install -o root -g root -m 0600 \
        "$state_root/tls/baseline/privkey.pem" \
        "$state_root/tls/active/privkey.pem"
    install -o fixture -g fixture -m 0644 \
        "$state_root/tls/candidate/fullchain.pem" \
        "$state_root/tls/staging/fullchain.pem"
    install -o fixture -g fixture -m 0600 \
        "$state_root/tls/candidate/privkey.pem" \
        "$state_root/tls/staging/privkey.pem"

    printf 'CertBaton disposable local fixture\n' >"$state_root/webroot/index.html"
    chown fixture:nginx "$state_root/webroot/index.html"
    chmod 0640 "$state_root/webroot/index.html"

    /usr/local/sbin/fixture-inject reset
    touch "$state_root/.initialized"
    chmod 0600 "$state_root/.initialized"
fi

for required in \
    "$state_root/ca/ca.crt" \
    "$state_root/tls/active/fullchain.pem" \
    "$state_root/tls/active/privkey.pem" \
    "$state_root/tls/staging/fullchain.pem" \
    "$state_root/tls/staging/privkey.pem"; do
    require_regular_file "$required"
done

chown root:root "$state_root" "$state_root/ssh" "$state_root/ca" "$state_root/inject"
chmod 0755 "$state_root" "$state_root/ssh"
chmod 0700 "$state_root/ca" "$state_root/inject"
chown -R fixture:fixture "$state_root/tls/staging"
chmod 0700 "$state_root/tls/staging"
chmod 0644 "$state_root/tls/staging/fullchain.pem"
chmod 0600 "$state_root/tls/staging/privkey.pem"

chown nginx:nginx /var/lib/nginx/tmp /var/lib/nginx/tmp/*
chmod 0750 /var/lib/nginx/tmp /var/lib/nginx/tmp/*

install -o root -g root -m 0644 "$state_root/ca/ca.crt" "$public_output/ca.crt"
install -o root -g root -m 0644 \
    "$state_root/ssh/ssh_host_ed25519_key.pub" \
    "$public_output/ssh_host_ed25519_key.pub"
install -o root -g root -m 0644 \
    "$state_root/tls/baseline/cert.pem" \
    "$public_output/baseline.crt"
install -o root -g root -m 0644 \
    "$state_root/tls/candidate/cert.pem" \
    "$public_output/candidate.crt"

/usr/sbin/sshd -t -f /etc/ssh/sshd_config
nginx -t -q -c /etc/nginx/nginx.conf

/usr/sbin/sshd -D -e -f /etc/ssh/sshd_config &
sshd_pid=$!
nginx -g 'daemon off;' -c /etc/nginx/nginx.conf &
nginx_pid=$!

stop_children() {
    kill -TERM "$sshd_pid" "$nginx_pid" 2>/dev/null || true
    wait "$sshd_pid" "$nginx_pid" 2>/dev/null || true
}

trap stop_children TERM INT

set +e
wait -n "$sshd_pid" "$nginx_pid"
status=$?
set -e
stop_children
exit "$status"
