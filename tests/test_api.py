from django.test import TestCase
import nmapreport.api as api


class ApiTestCase(TestCase):
	def setUp(self):
		self.nmap_newscan_once = {
			'request.method': 'POST',
            'POST': {
                'filename': 'testscan',
                'params': '-sT A -T4',
                'target': '192.168.1.1',
                },
            }

	def test_api_nmap_newscan(self):
		self.assertEqual(api.nmap_newScan(self.nmap_newscan_once), '/home/runner/work/WebMap/WebMap/nmapdashboard/nmapreport/nse')
