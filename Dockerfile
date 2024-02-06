FROM docker.io/python:3.12-alpine3.18

LABEL maintainer="Said Sef <saidsef@gmail.com> (saidsef.co.uk/)"

ENV PORT ${PORT:-8080}
ENV SCAPY_HISTFILE "/app/.scapy_history"
ENV SCAPY_USE_LIBPCAP "yes"
ENV VERSION 1.7.4

COPY requirements.txt .

RUN apk add -U --no-cache --repository http://dl-cdn.alpinelinux.org/alpine/edge/main \
        build-base gcc musl-dev cmake autoconf python3-dev libstdc++ openblas-dev jpeg-dev zlib-dev \
        bison libpng libpng-dev freetype freetype-dev libffi libffi-dev openssl openssl-dev \
        tcpdump imagemagick graphviz curl texlive libressl libpcap libpcap-dev libjpeg xdg-utils && \
    pip3 install --no-cache -r requirements.txt -Csetup-args=-Dblas=blas -Csetup-args=-Dlapack=lapack && \
    curl https://github.com/tsl0922/ttyd/releases/download/${VERSION}/ttyd.x86_64 -L -o /usr/local/bin/ttyd && \
    chmod +x /usr/local/bin/ttyd && \
    rm -rfv /var/cache/apk/*

WORKDIR /app

# GeoIP2 data directory
VOLUME ["/data"]

EXPOSE $PORT

ENTRYPOINT ttyd -W -6 -p $PORT sh
CMD ./scapy-${VERSION}/run_scapy
