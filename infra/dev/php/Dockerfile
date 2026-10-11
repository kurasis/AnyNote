FROM composer:2.10.3@sha256:af98f42dfff7c68ba8d53c2164fd9fde1087b7d449514baa38c418b1f6bc4bac AS composer
FROM php:8.4.26-fpm-trixie@sha256:1071b5609d16d60674f78eea8cf9bd7e9e79169ecb566d015c931c5ee789bb13

# Debian verifies signed repository metadata and package hashes. Never bypass it.
COPY trust/ /usr/local/share/ca-certificates/
RUN update-ca-certificates \
    && sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update --error-on=any \
    && apt-get install -y --no-install-recommends libicu-dev=76.1-4 libzip-dev=1.11.3-2 unzip \
    && docker-php-ext-install -j2 intl pdo_mysql zip \
    && rm -rf /var/lib/apt/lists/*
COPY --from=composer /usr/bin/composer /usr/local/bin/composer
COPY --chmod=0644 php.ini /usr/local/etc/php/conf.d/anynote.ini
COPY --chmod=0644 pool.conf /usr/local/etc/php-fpm.d/zz-anynote.conf
WORKDIR /app
USER 1000:1000
