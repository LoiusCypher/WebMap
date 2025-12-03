from django.test import TestCase
import nmapreport.nmap as nmap
from nmapreport.models import Scan
import copy


class NmapTestCase(TestCase):
	def setUp(self):
		self.scan_options = ['-sT', '-A', '-T4']
		self.sched = {
			'filename': 'testfile.xml',
			'options': ' '.join(self.scan_options),
			'target': '192.168.1.1/30',
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

	def test_nmap_generate_active_scan_file_path(self):
		self.assertEqual(nmap.genActiveScanFilePath(name=self.sched['params']['filename'], number=self.sched['number']), '/tmp/3_testfile.xml.active')

	def test_nmap_generate_finished_scan_file_name(self):
		self.assertEqual(nmap.genFinishedScanFileName(self.sched['lastrun'], sched['params']['filename']), 'webmapsched_763592814.9651988_testfile.xml')

	def test_nmap_genScanCmd(self):
		self.assertEqual(nmap.genScanCmd(name=self.sched['filename'],
                                         params=self.sched['options'],
                                         target=self.sched['target'],
                                         number=self.sched['number'],
                                         filepath=nmap.genActiveScanFilePath(name=self.sched['filename'],
                                                                             number=self.sched['number'])),
					['/usr/bin/nmap'] + self.scan_options +
					['--script=' + nmap.nsePath() + '/', '-oX', nmap.genActiveScanFilePath(name=self.sched['params']['filename'], number=self.sched['number']), self.sched['params']['target']])

	def test_nmap_runScan_successs(self):
		expected_strings = [
			'Starting Nmap 7.94SVN ( https://nmap.org ) at ',
			'Nmap done: 4 IP addresses (0 hosts up) scanned in'
		]
		retVal, active_scan_file_path, stdout, stderr = nmap.runScan(Scan(name=self.sched['params']['filename'], options=self.sched['params']['params'], target=self.sched['params']['target'], execution_counter=self.sched['number']))
		self.assertEqual(retVal, 0)
		self.assertEqual(active_scan_file_path, nmap.genActiveScanFilePath(name=self.sched['params']['filename'], number=self.sched['number']))
		self.assertEqual(stdout, '')
		lines = stderr.splitlines()
		self.assertEqual(len(lines), len(expected_strings))
		for lineNr, line in enumerate(lines):
			self.assertEqual(line[:len(expected_strings[lineNr])], expected_strings[lineNr])

	def test_nmap_runScan_fail(self):
		retVal, tmp_file_path, stdout, stderr = nmap.runScan(Scan(name=self.fail_sched['params']['filename'], options=self.fail_sched['params']['params'], target=self.fail_sched['params']['target'], execution_counter=self.fail_sched['number']))
		self.assertNotEqual(retVal, 0)
