FROM docker.io/python:3.13.7-alpine3.21

LABEL maintainer="Said Sef <saidsef@gmail.com> (saidsef.co.uk/)"

ENV PORT=${PORT:-8080}
ENV SCAPY_HISTFILE="/app/.scapy_history"
ENV SCAPY_USE_LIBPCAP="yes"
ENV VERSION=1.7.7

COPY requirements.txt .
# -Csetup-args=-Dblas=blas -Csetup-args=-Dlapack=lapack
RUN apk add -U --no-cache --repository http://dl-cdn.alpinelinux.org/alpine/edge/main \
        build-base gcc g++ musl-dev cmake autoconf python3-dev libstdc++ openblas-dev jpeg-dev zlib-dev \
        bison libpng libpng-dev freetype freetype-dev libffi libffi-dev openssl openssl-dev \
        tcpdump imagemagick graphviz curl texlive libressl libpcap libpcap-dev libjpeg xdg-utils \
        proj-dev proj-util proj geos geos-dev && \
    pip3 install --no-cache -r requirements.txt && \
    curl https://github.com/tsl0922/ttyd/releases/download/${VERSION}/ttyd.x86_64 -L -o /usr/local/bin/ttyd && \
    chmod +x /usr/local/bin/ttyd && \
    rm -rfv /var/cache/apk/*

# Copy the scripts folder while ignoring the charts folder
COPY scripts /app/scripts

WORKDIR /app

# GeoIP2 data directory
VOLUME ["/data"]

EXPOSE $PORT

ENTRYPOINT ttyd -W -6 -p $PORT sh
CMD ./scapy-${VERSION}/run_scapy
