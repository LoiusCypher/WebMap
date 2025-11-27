from django.test import TestCase
import nmapreport.nmap as nmap
import copy


class NmapTestCase(TestCase):
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

	def test_nmap_nse_path(self):
		self.assertEqual(nmap.nsePath(), '/home/runner/work/WebMap/WebMap/nmapdashboard/nmapreport/nse')
