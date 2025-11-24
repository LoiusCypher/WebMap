from django.test import TestCase
import nmapreport.nmap.cve as cve
from django.conf import settings
import os, copy

cdir = os.path.dirname(os.path.realpath(__file__))

class CveTestCase(TestCase):
	def setUp(self):
		self.std_cpe = {
		'cpe': {
			'192.168.1.1': {
				'cpe:/a:matt_johnston:dropbear_ssh_server:2020.80': 'cpe:/a:matt_johnston:dropbear_ssh_server:2020.80',
				'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
				'cpe:/a:busybox:busybox': 'cpe:/a:busybox:busybox',
				'cpe:/a:thekelleys:dnsmasq:2.82': 'cpe:/a:thekelleys:dnsmasq:2.82'
			},
			'192.168.1.53': {},
			'192.168.1.57': {
				'cpe:/a:openbsd:openssh:10.0p2': 'cpe:/a:openbsd:openssh:10.0p2',
				'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
					'cpe:/a:samba:samba:4': 'cpe:/a:samba:samba:4',
				'cpe:/a:redhat:cockpit': 'cpe:/a:redhat:cockpit'
			},
			'192.168.1.58': {
				'cpe:/a:apple:airtunes:377.40.00': 'cpe:/a:apple:airtunes:377.40.00'},
			'192.168.1.65': {},
			'192.168.1.70': {},
			'192.168.1.96': {},
			'192.168.1.99': {
				'cpe:/a:openbsd:openssh:9.8': 'cpe:/a:openbsd:openssh:9.8'},
			'192.168.1.122': {
				'cpe:/a:openbsd:openssh:10.0p2': 'cpe:/a:openbsd:openssh:10.0p2',
				'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
				'cpe:/a:igor_sysoev:nginx:1.21.5': 'cpe:/a:igor_sysoev:nginx:1.21.5'},
			'192.168.1.130': {
				'cpe:/a:vsftpd:vsftpd': 'cpe:/a:vsftpd:vsftpd',
				'cpe:/a:openbsd:openssh:6.0p1': 'cpe:/a:openbsd:openssh:6.0p1',
				'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
				'cpe:/a:apache:http_server': 'cpe:/a:apache:http_server',
				'cpe:/a:samba:samba': 'cpe:/a:samba:samba',
				'cpe:/a:plex:plex_media_server': 'cpe:/a:plex:plex_media_server'},
			'192.168.1.141': {},
			'192.168.1.64': {
				'cpe:/a:openbsd:openssh:9.2p1': 'cpe:/a:openbsd:openssh:9.2p1',
				'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel'}, '192.168.2.1': {},
			'192.168.2.100': {
				'cpe:/a:matt_johnston:dropbear_ssh_server:2020.80': 'cpe:/a:matt_johnston:dropbear_ssh_server:2020.80',
				'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
				'cpe:/a:busybox:busybox': 'cpe:/a:busybox:busybox',
				'cpe:/a:thekelleys:dnsmasq:2.82': 'cpe:/a:thekelleys:dnsmasq:2.82'
			},
			'192.168.2.106': {
				'cpe:/a:openbsd:openssh:10.0p2': 'cpe:/a:openbsd:openssh:10.0p2',
				'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
				'cpe:/a:golang:go': 'cpe:/a:golang:go',
				'cpe:/a:igor_sysoev:nginx': 'cpe:/a:igor_sysoev:nginx'},
			'192.168.2.112': {
				'cpe:/a:openbsd:openssh:10.0p2': 'cpe:/a:openbsd:openssh:10.0p2',
				'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
				'cpe:/a:apache:http_server:2.4.65': 'cpe:/a:apache:http_server:2.4.65'},
			'192.168.2.225': {
				'cpe:/a:openbsd:openssh:10.0p2': 'cpe:/a:openbsd:openssh:10.0p2',
				'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
				'cpe:/a:golang:go': 'cpe:/a:golang:go',
				'cpe:/a:igor_sysoev:nginx': 'cpe:/a:igor_sysoev:nginx'},
			'192.168.2.227': {
				'cpe:/a:openbsd:openssh:10.0p2': 'cpe:/a:openbsd:openssh:10.0p2',
				'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
				'cpe:/a:golang:go': 'cpe:/a:golang:go',
				'cpe:/a:python:wsgiref:0.2': 'cpe:/a:python:wsgiref:0.2'}
		},
		'cve': {
			'192.168.1.1': {},
			'192.168.1.53': {},
			'192.168.1.57': {},
			'192.168.1.58': {},
			'192.168.1.65': {},
			'192.168.1.70': {},
			'192.168.1.96': {},
			'192.168.1.99': {},
			'192.168.1.122': {},
			'192.168.1.130': {},
			'192.168.1.141': {},
			'192.168.1.64': {},
			'192.168.2.1': {},
			'192.168.2.100': {},
			'192.168.2.106': {},
			'192.168.2.112': {},
			'192.168.2.225': {},
			'192.168.2.227': {}
		}}

		self.new_cpe = {
			'cpe': {
				'192.168.2.1': {},
				'192.168.2.100': {},
				'192.168.2.106': {
					'cpe:/a:openbsd:openssh:10.0p2': 'cpe:/a:openbsd:openssh:10.0p2',
					'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
					'cpe:/a:golang:go': 'cpe:/a:golang:go',
					'cpe:/a:igor_sysoev:nginx': 'cpe:/a:igor_sysoev:nginx'},
				'192.168.2.112': {
					'cpe:/a:openbsd:openssh:10.0p2': 'cpe:/a:openbsd:openssh:10.0p2',
					'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
					'cpe:/a:apache:http_server:2.4.65': 'cpe:/a:apache:http_server:2.4.65'},
				'192.168.2.214': {},
				'192.168.2.225': {
					'cpe:/a:openbsd:openssh:10.0p2': 'cpe:/a:openbsd:openssh:10.0p2',
					'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
					'cpe:/a:golang:go': 'cpe:/a:golang:go',
					'cpe:/a:igor_sysoev:nginx': 'cpe:/a:igor_sysoev:nginx'},
				'192.168.2.227': {
					'cpe:/a:openbsd:openssh:10.0p2': 'cpe:/a:openbsd:openssh:10.0p2',
					'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
					'cpe:/a:golang:go': 'cpe:/a:golang:go',
					'cpe:/a:python:wsgiref:0.2': 'cpe:/a:python:wsgiref:0.2'
				}
			},
			'cve': {
				'192.168.2.1': {},
				'192.168.2.100': {},
				'192.168.2.106': {},
				'192.168.2.112': {},
				'192.168.2.214': {},
				'192.168.2.225': {},
				'192.168.2.227': {}
			}
		}

		self.tst_cpe = {
		'cpe': {
			'192.168.1.1': {
				'cpe:/a:matt_johnston:dropbear_ssh_server:2020.80': 'cpe:/a:matt_johnston:dropbear_ssh_server:2020.80',
				'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel',
				'cpe:/a:busybox:busybox': 'cpe:/a:busybox:busybox',
				'cpe:/a:thekelleys:dnsmasq:2.82': 'cpe:/a:thekelleys:dnsmasq:2.82'
			},
		},
		'cve': {
			'192.168.1.1': {},
		}}

	def test_cve_loadScan_std(self):
		cpe_cve_list = cve.loadScan(os.path.join(cdir,'.testfiles/std_cve.xml'))
		print(cpe_cve_list)
		self.assertEqual(cpe_cve_list, self.std_cpe)

	def test_cve_loadScan_new(self):
		cpe_cve_list = cve.loadScan(os.path.join(cdir,'.testfiles/new_cve.xml'))
		print(cpe_cve_list)
		self.assertEqual(cpe_cve_list, self.new_cpe)

	def test_cve_getCveOnline(self):
		cve_json = cve.getCveOnline(self.tst_cpe)
		print(cve_json)
		self.assertEqual(str(cve_json), self.std_cpe)

