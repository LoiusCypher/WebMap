from django.test import TestCase
import nmapreport.views
from django.conf import settings


class ViewsTestCase(TestCase):
	def setUp(self):
		self.cvejson = [[]]

	def test_cron_getCveOut_empty(self):
		self.assertEqual(views.getCveOut(self.cvejson), '/home/runner/work/WebMap/WebMap/nmapdashboard/nmapreport/nmap/nse')

	def test_cron_getCveOut_new(self):
		cve_test = cve.loadScan(os.path.join(cdir, '.testfiles/new_cve.xml'))
		self.assertEqual(views.getCveOut(cve_test), '/home/runner/work/WebMap/WebMap/nmapdashboard/nmapreport/nmap/nse')

