# The tag is descriptive; the OCI index digest is the actual immutable pin.
FROM alpine:3.22.1@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1

RUN apk add --no-cache \
        bash \
        curl \
        doas \
        nginx \
        openssh-server \
        openssl \
    && adduser -D -u 10001 -h /home/fixture -s /bin/ash fixture \
    && addgroup fixture nginx \
    && passwd -l fixture \
    && mkdir -p \
        /fixture-input/ssh \
        /fixture-output/pki \
        /fixture-state \
        /srv \
        /run/nginx \
        /run/sshd \
        /var/lib/nginx/tmp/client \
        /var/lib/nginx/tmp/fastcgi \
        /var/lib/nginx/tmp/proxy \
        /var/lib/nginx/tmp/scgi \
        /var/lib/nginx/tmp/uwsgi \
    && ln -s /fixture-state /srv/certbaton

COPY nginx.conf /etc/nginx/nginx.conf
COPY sshd_config /etc/ssh/sshd_config
COPY doas.conf /etc/doas.conf
COPY entrypoint.sh /usr/local/bin/fixture-entrypoint
COPY fixture-healthcheck /usr/local/bin/fixture-healthcheck
COPY certbaton-fixture-control /usr/local/sbin/certbaton-fixture-control
COPY fixture-inject /usr/local/sbin/fixture-inject

RUN chown root:root \
        /etc/nginx/nginx.conf \
        /etc/ssh/sshd_config \
        /etc/doas.conf \
        /usr/local/bin/fixture-entrypoint \
        /usr/local/bin/fixture-healthcheck \
        /usr/local/sbin/certbaton-fixture-control \
        /usr/local/sbin/fixture-inject \
    && chmod 0444 /etc/nginx/nginx.conf /etc/ssh/sshd_config \
    && chmod 0400 /etc/doas.conf \
    && chmod 0555 \
        /usr/local/bin/fixture-entrypoint \
        /usr/local/bin/fixture-healthcheck \
        /usr/local/sbin/certbaton-fixture-control \
    && chmod 0500 /usr/local/sbin/fixture-inject

EXPOSE 22 80 443

ENTRYPOINT ["/usr/local/bin/fixture-entrypoint"]
