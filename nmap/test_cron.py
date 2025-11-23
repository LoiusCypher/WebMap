from django.test import TestCase
import cron
from django.conf import settings
import os

class CronTestCase(TestCase):
	def setUp(self):
		self.params = ['-sT', '-A', '-T4']
		self.sched = {
			'number': 3,
			'lastrun': 763592814.9651988,
			'params': {
				'filename': 'testfile.xml',
				'params': ' '.join(self.params),
				'target': '192.168.1.1/32'
			}
		}
        self.fail_sched = self.sched[:]
		self.fail_sched['params']['params'] = '-xX'

	def test_cron_generate_active_scan_file_path(self):
		self.assertEqual(cron.genActiveScanFilePath(self.sched),'/tmp/3_testfile.xml.active')

	def test_cron_generate_finished_scan_file_name(self):
		self.assertEqual(cron.genFinishedScanFileName(self.sched),'webmapsched_763592814.9651988_testfile.xml')

	def test_cron_genScanCmd(self):
		self.assertEqual(cron.genScanCmd(self.sched), [ '/usr/bin/nmap' ]+self.params+['--script='+os.path.join(os.path.dirname(os.path.realpath(__file__)),'nse',)+'/', '-oX', cron.genActiveScanFilePath(self.sched), self.sched['params']['target']])

	def test_cron_runScan_successs(self):
		xpected_string_start='[DONE] Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-11-23 08:46 UTC\n - Nmap done: 256 IP addresses (0 hosts up) scanned in 51.68 seconds'
		retVal, active_scan_file_path, stdout, stderr = cron.runScan(self.sched)
		self.assertEqual(retVal,0)
		self.assertEqual(active_scan_file_path,cron.genActiveScanFilePath(self.sched))
		self.assertEqual(stdout,'')
		self.assertEqual(stderr[:len(expected_string_start)],expected_string_start)

	def test_cron_runScan_fail(self):
		retVal, tmp_file_path, stdout, stderr = cron.runScan(self.fail_sched)
		self.assertNotEqual(retVal,0)

