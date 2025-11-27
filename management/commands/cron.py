from django.core.management.base import BaseCommand, CommandError
from nmapreport.models import ScanJob
# import nmapreport.nse.cron as cron
import os
import re
import json
import time
import shlex
import shutil
import subprocess
from datetime import datetime


cdir = os.path.dirname(os.path.realpath(__file__))


def nsePath():
	return os.path.join(cdir, 'nse')


def gethours(f):
	return {
		'1h': 3600,
		'1d': 86400,
		'1w': 604800,
		'1m': 2592000
	}[f]


def genActiveScanFilePath(sched):
	return '/tmp/' + str(sched['number']) + '_' + sched['params']['filename'] + '.active'


def genFinishedScanFileName(sched):
	return 'webmapsched_' + str(sched['lastrun']) + '_' + sched['params']['filename']


def genScanCmd(sched):
	return [shutil.which('nmap')] + shlex.split(sched['params']['params']) + ['--script=' + nsePath() + '/',
		'-oX', genActiveScanFilePath(sched), sched['params']['target']]


def runScan(sched):
	nmap_active_scan_out = genActiveScanFilePath(sched)
	nmapprocess = subprocess.Popen(genScanCmd(sched), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
	stdout, stderr = nmapprocess.communicate()
	print('[DONE] ' + stderr + stdout)
	return nmapprocess.returncode, nmap_active_scan_out, stderr, stdout


class Command(BaseCommand):

    def cronMe(self):

        schedfiles = os.listdir('/opt/schedule/')

        self.stdout.write(str(ScanJob.objects.all().count()))
        for sched in ScanJob.objects.all():
            stdout.write(str(sched.date_last_execution))
            stdout.write(str(sched.execution_interval_numer))
            nextrun = sched.date_last_execution + gethours(sched.execution_interval_numer)
            print("[RUN]   scan:" + sched.name + " id:" + str(sched.id) + " (nextrun:" + str(nextrun) + " / now:" + str(datetime.now()) + ")")
            if nextrun <= datetime.now():
                sched.date_last_execution += datetime.now() + gethours(sched.execution_interval_numer)
                sched.execution_counter += 1
                self.stdout.write(str(sched.execution_counter))
                sched.Save()

                    # errorCode, nmap_active_scan_out, stdout, stderr = runScan(sched)
                    # print('[DONE] ' + stderr + stdout)
                    # if errorCode != 0:
                        # os.remove(nmap_active_scan_out)
                    # else:
                        # time.sleep(5)
                        # nmap_out_file = genFinishedScanFileName(sched)
                        # shutil.move(nmap_active_scan_out, '/opt/xml/' + nmap_out_file)
                        # nmapout = os.popen('python3 ' + cdir + '/cve.py webmapsched_' + str(sched['lastrun']) + '_' + sched['params']['filename'] + '').readlines()
                        # print(nmapout)
                    # time.sleep(10)
                # else:
                    # print("[SKIP]  scan:" + sched['params']['filename'] + " id:" + str(sched['number']) + " (nextrun:" + str(nextrun) + " / now:" + str(time.time()) + ")")
                # nextsched = min(nextsched, nextrun)
            # print("[DEBUG] nextsched:" + str(nextsched - time.time()))


    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Successfully closed poll '))
        self.cronMe()
