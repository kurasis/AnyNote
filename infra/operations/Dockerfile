# Build from a sanitized release context prepared by scripts/p16-stack.py.
# The base is built from infra/dev/php/Dockerfile with pinned upstream digests.
ARG ANYNOTE_PHP_IMAGE=anynote-p03-php:8.4.26
FROM ${ANYNOTE_PHP_IMAGE}
USER root
RUN docker-php-ext-install -j2 pcntl
COPY --chown=0:0 --chmod=0755 rootfs/ /
USER 1000:1000
