FROM ghcr.io/astral-sh/uv:latest AS uv

FROM docker.io/python:3.14-alpine3.23

LABEL maintainer="Said Sef <saidsef@gmail.com> (saidsef.co.uk/)"

ENV PORT=${PORT:-8080}
ENV SCAPY_HISTFILE="/app/.scapy_history"
ENV SCAPY_USE_LIBPCAP="yes"
ENV VERSION=1.7.7
ENV XDG_CACHE_HOME="/tmp"
ENV IPYTHONDIR="/tmp/.ipython"

WORKDIR /app

COPY --from=uv /uv /uvx /usr/local/bin/
COPY pyproject.toml uv.lock /app/

RUN apk upgrade --no-cache && \
    apk add -U --no-cache --repository http://dl-cdn.alpinelinux.org/alpine/edge/main \
        build-base gcc g++ musl-dev cmake autoconf python3-dev libstdc++ openblas-dev jpeg-dev zlib-dev \
        bison libpng libpng-dev freetype freetype-dev libffi libffi-dev openssl openssl-dev \
        tcpdump imagemagick graphviz curl libressl libpcap libpcap-dev libjpeg xdg-utils \
        proj-dev proj-util proj geos geos-dev \
        texlive ghostscript && \
    uv export --frozen --no-dev --no-hashes --format requirements-txt | \
        uv pip install --system --no-cache -r - && \
    curl https://github.com/tsl0922/ttyd/releases/download/${VERSION}/ttyd.x86_64 -L -o /usr/local/bin/ttyd && \
    chmod +x /usr/local/bin/ttyd && \
    rm -rfv /var/cache/apk/*

COPY scripts /app/scripts

# GeoIP2 data directory
VOLUME ["/data"]

EXPOSE $PORT

ENTRYPOINT ttyd -W -6 -d 3 -p $PORT sh
CMD ./scapy-${VERSION}/run_scapy
