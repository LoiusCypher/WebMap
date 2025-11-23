from django.test import TestCase
import cron

from django.conf import settings
import os, re, json, time
import subprocess, shutil, shlex

class CronTestCase(TestCase):
	def setUp(self):
		self.sched = json.loads({
			'number': 0
			'params': {
				'filename': 'testfile.xml'
			}
		})
	def test_cron_generate_tmp_file_name():
		self.assertEqual(cron.cron_gen_tmp_file_name(self.sched),"o")

