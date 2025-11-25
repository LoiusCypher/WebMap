from django.test import TestCase
import django.nmapreport.views
from django.conf import settings
import os


class ViewsTestCase(TestCase):
	def setUp(self):
		self.cvejson = [[]]

	def test_cron_getCveOut_empty(self):
		self.assertEqual(views.getCveOut(self.cvejson), '/home/runner/work/WebMap/WebMap/nmapdashboard/nmapreport/nmap/nse')

	def test_cron_getCveOut_new(self):
		cve_test = cve.loadScan(os.path.join(views.cdir, '.testfiles/new_cve.xml'))
		self.assertEqual(views.getCveOut(cve_test), '/home/runner/work/WebMap/WebMap/nmapdashboard/nmapreport/nmap/nse')

