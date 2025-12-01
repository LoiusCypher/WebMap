from django.test import TestCase
from django.test import Client
import nmapreport.api as api


class reqShim(object):
    pass

class ApiTestCase(TestCase):

    def setUp(self):
        self.nmap_newscan_once = reqShim()
        self.nmap_newscan_once.request = reqShim()
        self.nmap_newscan_once.request.method = 'POST'
        self.nmap_newscan_once.POST = {
                'filename': 'testscan',
                'params': '-sT A -T4',
                'target': '192.168.1.1',
        }


    def test_api_nmap_newscan_call(self):
        self.assertEqual(api.nmap_newscan(self.nmap_newscan_once), '/home/runner/work/WebMap/WebMap/nmapdashboard/nmapreport/nse')


    def test_api_nmap_newscan_post(self):
        c = Client()
        response = c.post('/api/v1/nmap/sxan/new', self.nmap_newscan_once)
        self.assertEqual(api.nmap_newscan(self.nmap_newscan_once), '/home/runner/work/WebMap/WebMap/nmapdashboard/nmapreport/nse')
