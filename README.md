# Scapy Containerised

Scapy is a powerful Python-based interactive packet manipulation program and library.

Scapy enables the user to send, sniff and dissect and forge network packets. This capability allows construction of tools that can probe, scan or attack networks.

Scapy is usable either as a shell or as a library. For further details, please head over to [Getting started with Scapy](https://scapy.readthedocs.io/en/latest/introduction.html), which is part of the documentation.

## Prerequisite
 - Container runtime (needs to run privileged mode)
 - Some Python Knowledge
 - Have read [Scapy docs](https://scapy.readthedocs.io/en/latest/introduction.html)

## Installation

Follow these steps to build:

```shell
git clone https://github.com/saidsef/scapy-containerised
```

```shell
docker build -t saidsef/scapy-containerised:latest .
```

```shell
docker run -d --net=host --privileged -v /path/to/geoip2:/data saidsef/scapy-containerised:latest
```

Than visit:
```shell
http://localhost:8080
```

In the browser termonal type:
```shell
python -m scapy
```

To start Scapy in interactive mode. 

## Deployment

```shell
kubectl apply -k ./deployment
```

## Sniff Packets

```shell
> load_layer("tls")
> sniff(iface="ens3", prn=lambda x: x.show(), lfilter=lambda x: TLS in x, count=100)
```