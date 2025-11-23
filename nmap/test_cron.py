from django.test import TestCase
import cron
#import json

class CronTestCase(TestCase):
	def setUp(self):
		self.sched = {
			'number': 3,
			'params': {
				'filename': 'testfile.xml',
				'params': '-sT -A -T4',
				'target': '192.168.2.112/24'
			}
		}
	def test_cron_generate_tmp_file_name(self):
		self.assertEqual(cron.cron_gen_tmp_file_name(self.sched),'/tmp/3_testfile.xml.active')
	def test_cron_gen_nmap_list(self):
		self.assertEqual(cron_gen_nmap_list(self.sched),'/tmp/3_testfile.xml.active')

