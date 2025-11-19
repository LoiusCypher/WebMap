<p align="center">
<img width="300" src="https://i.imgur.com/puyIfHT.jpg" /><br>
A Web Dashbord for Nmap XML Report 
</p>

## Table Of Contents
- [Usage](#usage)
- [Features](#features)
- [Third Parts](#third-parts)
- [Security Issues](#security-issues)

## Screenshot
<img src="https://i.imgur.com/ELZfqd0.png" /><br>
<img src="https://i.imgur.com/KsBv1S0.png" /><br>
<img src="https://i.imgur.com/g27mcc3.png" /><br>
<br>

## Usage
You should use this with docker, just by sending this command:
```bash
$ mkdir /tmp/cybr-capstone
$ docker build -t cybr-capstone <path to Dockerfile> --no-cache
$ docker run -d \
         --name cybr-capstone \
         -h cybr-capstone \
         -p 8000:8000 \
         -v /tmp/cybr-capstone:/opt/xml \
         cybr-capstone

$ # now you can run Nmap and Nikto Scans and save the XML Reports on /tmp/cybr-capstone
$ mkdir /tmp/cybr-capstone/<Scan Directory>
$ mkdir /tmp/cybr-capstone/<Scan Directory>/nmap
$ mkdir /tmp/cybr-capstone/<Scan Directory>/nikto
$ nmap -sT -A -T4 -oX /tmp/cybr-capstone/<Scan Directory>/nmap/mynmapscan.xml 192.168.1.0/24
$ nikto -h <host> -Formal xml -output /tmp/cybr-capstone/<Scan Directory>/nikto/myniktoscan.xml
```
Now point your browser to http://localhost:8000

### Generate new token
In order to access to the WebMap dashboard, you need a token. You can create a new token with:
```bash
$ docker exec -ti cybr-capstone /root/token
```

### Run without Docker
This project is designed to run on a Docker container. IMHO it isn't a good idea to run this on a custom Django installation, 
but if you need it you can find all building steps inside the [Dockerfile](https://github.com/SabyasachiRana/WebMap/blob/master/docker/Dockerfile).


## Features
- Import and parse Nmap and Nikto XML files
- Statistics and Charts on discovered services, ports, OS, etc...
- Inspect a single host by clicking on its IP address
- Attach labels on a host
- Insert notes for a specific host

## Network View
![WebMap](https://i.imgur.com/j77jQz9.png)

## Third Parts
- [Django](https://www.djangoproject.com)
- [Materialize CSS](https://materializecss.com)
- [Clipboard.js](https://clipboardjs.com)
- [Chart.js](https://www.chartjs.org)
- [Wkhtmltopdf](https://wkhtmltopdf.org)
- [API cve.circl.lu](https://cve.circl.lu)
- [vis.js](http://visjs.org/)

## Security Issues
This app is not intended to be exposed to the internet, but to be used as localhost web application. Please, **DO NOT expose** this app to the internet, use your localhost or, 
in case you can't do it, take care to filter who and what can access to WebMap with a firewall rule or something like that. 
Exposing this app to the whole internet could lead not only to a stored XSS but also to a leakage of sensitive/critical/private 
informations about your port scan. Please, be smart.

