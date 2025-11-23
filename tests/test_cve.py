from django.test import TestCase
import nmapreport.nmap.cve as cve
from django.conf import settings
import os, copy

cdir = os.path.dirname(os.path.realpath(__file__))

class CveTestCase(TestCase):
	def setUp(self):
		self.scan_options = ['-sT', '-A', '-T4']
		self.sched = {
			'number': 3,
			'lastrun': 763592814.9651988,
			'params': {
				'filename': 'testfile.xml',
				'params': ' '.join(self.scan_options),
				'target': '192.168.1.1/30'
			}
		}
		self.fail_sched = copy.deepcopy(self.sched)
		self.fail_sched['params']['params'] = '-xX'

	def test_cve_getcve(self):
		cpe_list, cve_list = cve.loadScan(os.path.join(cdir,'.testfiles/std_cve.xml'))

