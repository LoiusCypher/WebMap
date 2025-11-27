from django.shortcuts import render
from django.http import HttpResponse
from django.conf import settings
import os, re, json, hashlib, time


def nmap_scaninfo(request):
	tmpfiles = os.listdir('/tmp/')

	res = {'out':[], 'scans':{}}

	for ff in tmpfiles:
		if re.search(r'\.xml.active$', ff) is not None:
			f = ff[0:-7]
			res['scans'][f] = {'status':'active'}
			with open('/tmp/'+ff) as n:
				lines = n.readlines()
				for line in lines:
					#res['out'].append(line.strip())
					# <nmaprun scanner="nmap" args="nmap -oG /tmp/test.grep -oX /tmp/scan.xml -sT -sV -sC -T5 scanme.nmap.org" start="1541780258" startstr="Fri Nov  9 16:17:38 2018" version="7.60" xmloutputversion="1.04">

					rx = re.search(r'args\=.+\-oX \/tmp\/(.+\.xml).+ start\=.+ startstr\=.(.+). version\=', line.strip())
					if rx is not None:
						res['scans'][f]['filename'] = rx.group(1)
						res['scans'][f]['startstr'] = rx.group(2)

					rx = re.search(r'scaninfo type\=.(.+). protocol\=.(.+). numservices', line.strip())
					if rx is not None:
						res['scans'][f]['type'] = rx.group(1)
						res['scans'][f]['protocol'] = rx.group(2)

					# <finished time="1541780323" timestr="Fri Nov  9 16:18:43 2018" elapsed="65.31" summary="Nmap done at Fri Nov  9 16:18:43 2018; 1 IP address (1 host up) scanned in 65.31 seconds" exit="success"/><hosts up="1" down="0" total="1"/>
					rx = re.search(r'finished .+ summary\=.(.+). exit\=', line.strip())
					if rx is not None:
						res['scans'][f]['status'] = 'finished'
						res['scans'][f]['summary'] = rx.group(1)

	return HttpResponse(json.dumps(res, indent=4), content_type="application/json")
