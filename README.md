# Scapy Containerised

This gives you a shell inside container/namespace via TTYD, and you can use Scapy to analyse network traffic. 

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
docker run -d --net=host --privileged -v /path/to/geoip2:/data docker.io/saidsef/scapy-containerised:latest
```

> GeoIP data sets can be download from [P3TERX](https://github.com/P3TERX/GeoLite.mmdb) 

Than visit:

```shell
http://localhost:8080
```

In the browser termonal type:

```shell
python -m scapy.__init__
```

To start Scapy in interactive mode.

## Deployment

> To expose host interface to container enable `hostNetwork: true` in `deployment.yml` file.  [Consider security implications](https://kubernetes.io/docs/concepts/configuration/overview/)

> Make certain the `PORT` isn't already bound to another service - if you choose to run the service on a different PORT make sure you update the relevant fields.

### HELM

```shell
helm repo add scapy https://saidsef.github.io/scapy-containerised/
helm repo update
helm upgrade --install scapy scapy/scapy --namespace scapy --create-namespace
```

### Kubectl

```shell
kubectl apply -k ./deployment
```

To view, bind Kubernetes service port loaclly:

```shell
kubectl port-forward --namespace scapy svc/scapy 8080:8080
```

Than visit:

```shell
http://localhost:8080
```

## Sniff Packets

To list available layers:

```python
help(scapy.layers)
```
Sniff function specification documentation

```python
print sniff.__doc__
```

```python
load_layer("http")
get_if_list()
sniff(iface="eth0", prn=lambda x: x.show(), lfilter=lambda x: HTTP in x, count=100)
```
> https://scapy.readthedocs.io/en/latest/api/scapy.layers.html
> To load layers `tls` you might need to downgrade `cryptography` <= v38

The routes are stores in `conf.route`. You can use it to display the routes, or get specific routing:

```shell
conf.route
```

## Plot unsing Matplotlib

For some special features, Scapy will need some dependencies to be installed.

```python
p=sniff(iface="any", count=50)
p.plot(lambda x:len(x))
```
> https://scapy.readthedocs.io/en/latest/installation.html#optional-dependencies

## PDF Dump using `pxy`

```python
p=IP()/ICMP()
p.pdfdump("test.pdf", target="> /tmp")
```

## Source

Our latest and greatest source of scapy-containerised can be found on [GitHub](#deployment). Fork us!

## Contributing

We would :heart: you to contribute by making a [pull request](https://github.com/saidsef/scapy-containerised/pulls).

Please read the official [Contribution Guide](./CONTRIBUTING.md) for more information on how you can contribute.
