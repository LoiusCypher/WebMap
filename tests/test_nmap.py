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

	def test_nmap_generate_active_scan_file_path(self):
		self.assertEqual(nmap.genActiveScanFilePath(self.sched.params.filename, self.sched.params.params, self.sched.params.target), '/tmp/3_testfile.xml.active')

	def test_nmap_generate_finished_scan_file_name(self):
		self.assertEqual(nmap.genFinishedScanFileName(self.sched), 'webmapsched_763592814.9651988_testfile.xml')

	def test_nmap_genScanCmd(self):
		self.assertEqual(nmap.genScanCmd(self.sched.params.filename, self.sched.params.params, self.sched.params.target),
					['/usr/bin/nmap'] + self.scan_options +
					['--script=' + nmap.nsePath() + '/', '-oX', nmap.genActiveScanFilePath(self.sched), self.sched['params']['target']])

	def test_nmap_runScan_successs(self):
		expected_strings = [
			'Starting Nmap 7.94SVN ( https://nmap.org ) at ',
			'Nmap done: 4 IP addresses (0 hosts up) scanned in'
		]
		retVal, active_scan_file_path, stdout, stderr = nmap.runScan(self.sched)
		self.assertEqual(retVal, 0)
		self.assertEqual(active_scan_file_path, nmap.genActiveScanFilePath(self.sched))
		self.assertEqual(stdout, '')
		lines = stderr.splitlines()
		self.assertEqual(len(lines), len(expected_strings))
		for lineNr, line in enumerate(lines):
			self.assertEqual(line[:len(expected_strings[lineNr])], expected_strings[lineNr])

	def test_nmap_runScan_fail(self):
		retVal, tmp_file_path, stdout, stderr = nmap.runScan(self.fail_sched)
		self.assertNotEqual(retVal, 0)
