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
        print(str(ScanJob.objects.all().count()))
        timeToWait = nmap.gethours('1m')
        self.stdout.write(str(ScanJob.objects.all().count()))
        for sched in ScanJob.objects.all():
            self.stdout.write(str(sched.date_last_execution))
            self.stdout.write(str(sched.execution_interval_numer))
            nextrun = sched.date_last_execution + nmap.gethours(sched.execution_interval_numer)
            print("[RUN]  Y scan:" + sched.name + " id:" + str(sched.id) + " (nextrun:" + str(nextrun) + " / now:" + str(datetime.now()) + ")")
            timeToWait = nextrun - datetime.now()
            if nextrun <= datetime.now():
                sched.date_last_execution = datetime.now()
                nextrun = sched.date_last_execution + nmap.gethours(sched.execution_interval_numer)
                sched.execution_counter += 1
                self.stdout.write(str(sched.execution_counter))
                sched.save()
                scan = Scan(sched.name, options=sched.options, target=sched.target, execution_counter=sched.execution_counter)
            else:
                scan = Scan(sched.name, options=sched.options, target=sched.target)
            if timeToWait > nextrun - datetime.now():
                timeToWait = nextrun - datetime.now()
            scan.save()
        self.executeNextWaitingScan()
        print(timeToWait)
        return timeToWait

    def executeNextWaitingScan(self):
        try:
            waitingScan = Scan.objects.filter(started=None).order_by('created')[0]
            print("[CRON]  Starting scan")
            nmap.runScan(waitingScan)
            print("[CRON]  scan completed")
        except IndexError:
            print("[CRON]  No scans waiting")

    def handle(self, *args, **options):
        self.cronTick()
