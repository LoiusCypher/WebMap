from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from nmapreport.models import Scan
from datetime import datetime
import os
import re
import json
import time
import shlex
import shutil
import subprocess


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


def genFinishedScanFileName(sched):
	return 'webmapsched_' + str(sched['lastrun']) + '_' + sched['params']['filename']


def genActiveScanFilePath(name, number):
    return '/tmp/' + str(number) + '_' + name + '.active'


def genScanCmd(name, params, target, number, filepath):
    return [shutil.which('nmap')] \
            + shlex.split(params) \
            + ['--script=' + nsePath() + '/', '-oX', filepath, target]


def runScan(scan):
    nmap_active_scan_out = genActiveScanFilePath(scan.name, scan.execution_counter)
    scan.started = timezone.now()
    scan.save()
    nmapprocess = subprocess.Popen(genScanCmd(scan.name, scan.options, scan.target, nmap_active_scan_out),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = nmapprocess.communicate()
    scan.ended = timezone.now()
    scan.save()
    finishedFile = genFinishedScanFileName(sched))
    shutil.move(nmap_active_scan_out, '/opt/xml/' + finishedFile
    nmapout = os.popen('python3 ' + cdir + '/cve.py ' + finishedFile + '').readlines()
    print('[DONE] ' + stderr + stdout)
    return nmapprocess.returncode, nmap_active_scan_out, stderr, stdout
