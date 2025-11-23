from django.test import TestCase
import cron
from django.conf import settings
import os

class CronTestCase(TestCase):
	def setUp(self):
		self.params = ['-sT', '-A', '-T4']
		self.sched = {
			'number': 3,
			'params': {
				'filename': 'testfile.xml',
				'params': ' '.join(self.params),
				'target': '192.168.2.112/24'
			}
		}
	def test_cron_generate_tmp_file_name(self):
		self.assertEqual(cron.cron_gen_tmp_file_name(self.sched),'/tmp/3_testfile.xml.active')
	def test_cron_gen_nmap_list(self):
		self.assertEqual(cron.cron_gen_nmap_list(self.sched), [ '/usr/bin/nmap' ]+self.params+['--script='+os.path.join(os.path.dirname(os.path.realpath(__file__)),'nse',)+'/', '-oX', cron.cron_gen_tmp_file_name(self.sched), self.sched['params']['target']])
	def test_cron_run_scan(self):
		self.assertEqual(cron.cron_run_scan(self.sched),'/tmp/3_testfile.xml.active')

