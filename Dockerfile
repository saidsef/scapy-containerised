FROM python:3-alpine

LABEL maintainer="Said Sef <saidsef@gmail.com> (saidsef.co.uk/)"

ENV PORT ${PORT:-8080}

WORKDIR /app

COPY requirements.txt .

RUN apk add -U --no-cache --repository http://dl-cdn.alpinelinux.org/alpine/edge/main \
        build-base gcc musl-dev python3-dev libstdc++ \
        libpng libpng-dev freetype freetype-dev libffi libffi-dev openssl openssl-dev \
        tcpdump imagemagick graphviz ttyd texlive libressl libpcap && \
    pip install --no-cache -r requirements.txt && \
    apk del --purge build-base freetype-dev gcc musl-dev python3-dev libffi-dev libpng-dev libstdc++ openssl-dev && \
    rm -rfv /var/cache/apk/*

# GeoIP2 data directory
VOLUME ["/data"]

EXPOSE $PORT

ENTRYPOINT ttyd -p $PORT -d
CMD python -m scapy.__init__