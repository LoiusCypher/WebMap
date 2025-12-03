from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from nmapreport.models import Scan
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
from nmapreport import cve


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


def genFinishedScanFileName(name, lastrun):
	scanmd5 = hashlib.md5(str(name).encode('utf-8')).hexdigest()
	return 'webmapsched_' + str(lastrun) + '_' + scanmd5


def genActiveScanFilePath(name, number):
    return '/tmp/' + str(number) + '_' + name + '.active'


def genScanCmd(name, params, target, filepath):
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
    print('[DONE] ' + stderr + stdout)
    return nmapprocess.returncode, nmap_active_scan_out
