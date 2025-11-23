from django.test import TestCase
import cron
#import json

class CronTestCase(TestCase):
	def setUp(self):
#		self.sched = json.loads({
		self.sched = {
			'number': 3,
			'params': {
				'filename': 'testfile.xml'
			}
		}
	def test_cron_generate_tmp_file_name(self):
		self.assertEqual(cron.cron_gen_tmp_file_name(self.sched),'/tmp/3_testfile.xml.active')

