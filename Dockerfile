FROM python:3.7-alpine

LABEL maintainer="Said Sef <saidsef@gmail.com> (saidsef.co.uk/)"

ENV PORT ${PORT:-8080}

WORKDIR /app

COPY requirements.txt .

RUN apk add -U --no-cache --repository http://dl-cdn.alpinelinux.org/alpine/edge/main \
        build-base gcc musl-dev python3-dev python3-setuptools libstdc++ openblas-dev jpeg-dev zlib-dev \
        libpng libpng-dev freetype freetype-dev libffi libffi-dev openssl openssl-dev \
        tcpdump imagemagick graphviz ttyd texlive libressl libpcap libjpeg && \
    pip3 install --no-cache -r requirements.txt && \
    apk del --purge build-base freetype-dev gcc musl-dev python3-dev libffi-dev libpng-dev libstdc++ openssl-dev openblas-dev jpeg-dev zlib-dev && \
    rm -rfv /var/cache/apk/*

ADD https://github.com/secdev/scapy/archive/master.zip /app

# GeoIP2 data directory
VOLUME ["/data"]

EXPOSE $PORT

ENTRYPOINT ttyd -p $PORT sh
CMD ./run_scapy