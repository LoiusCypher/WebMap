from django.core.management.base import BaseCommand, CommandError
from nmapreport.models import Scan, ScanJob
import nmapreport.nmap as nmap
# import nmapreport.nse.cron as cron
import os
import re
import json
import time
import shlex
import shutil
import subprocess
from datetime import datetime

class Command(BaseCommand):

    def cronTick(self):
        self.stdout.write(str(ScanJob.objects.all().count()))
        for sched in ScanJob.objects.all():
            self.stdout.write(str(sched.date_last_execution))
            self.stdout.write(str(sched.execution_interval_numer))
            nextrun = sched.date_last_execution + nmap.gethours(sched.execution_interval_numer)
            print("[RUN]   scan:" + sched.name + " id:" + str(sched.id) + " (nextrun:" + str(nextrun) + " / now:" + str(datetime.now()) + ")")
            if nextrun <= datetime.now():
                sched.date_last_execution += datetime.now() + nmap.gethours(sched.execution_interval_numer)
                sched.execution_counter += 1
                self.stdout.write(str(sched.execution_counter))
                sched.save()
                scan = Scan(sched.name, options=sched.options, target=sched.target, execution_counter=sched.execution_counter)
            else:
                scan = Scan(sched.name, options=sched.options, target=sched.target)
            scan.save()
            nmap.runScan(scan)

            #        # errorCode, nmap_active_scan_out, stdout, stderr = runScan(sched)
            #        # print('[DONE] ' + stderr + stdout)
            #        # if errorCode != 0:
            #            # os.remove(nmap_active_scan_out)
            #        # else:
            #            # time.sleep(5)
            #            # nmap_out_file = genFinishedScanFileName(sched)
            #            # shutil.move(nmap_active_scan_out, '/opt/xml/' + nmap_out_file)
            #            # nmapout = os.popen('python3 ' + cdir + '/cve.py webmapsched_' + str(sched['lastrun']) + '_' + sched['params']['filename'] + '').readlines()
            #            # print(nmapout)
            #        # time.sleep(10)
            #    # else:
            #        # print("[SKIP]  scan:" + sched['params']['filename'] + " id:" + str(sched['number']) + " (nextrun:" + str(nextrun) + " / now:" + str(time.time()) + ")")
            #    # nextsched = min(nextsched, nextrun)
            # print("[DEBUG] nextsched:" + str(nextsched - time.time()))


    def handle(self, *args, **options):
        self.cronTickMe()
