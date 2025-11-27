from django.conf import settings
from django.db import models
from django.core.validators import RegexValidator
from datetime import datetime
import hashlib
import os


class Note(models.Model):
    id = models.AutoField(primary_key=True)
    scanfilemd5 = models.CharField(
        max_length=32,
        validators=[
            RegexValidator(
                regex='^[a-f0-9]$',
                message='Invalid MD5 tag',
            ),
        ]
    )
    hashstr  = models.CharField(
        max_length=32,
        validators=[
            RegexValidator(
                regex='^[a-f0-9]$',
                message='Invalid MD5 tag',
            ),
        ]
    )
    text = models.TextField()

    def file_name(self):
        self.clean()
        return os.path.join(os.path.join(settings.BASE_DIR, 'notes'), self.scanfilemd5 + '_' + self.hashstr + '.notes')


class Scan(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.TextField()
    scan_start = models.DateTimeField(default=datetime.now, blank=True)
    scan_end = models.DateTimeField()
    options = models.CharField(max_length=80)
    target = models.CharField(max_length=80)
    execution_counter = models.IntegerField(default=0)


class ScanJob(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=75)
    options = models.CharField(max_length=75)
    target = models.CharField(max_length=75)
    execution_interval_numer = models.SmallIntegerField(help_text='Interval number for days/hours/etc.')
    execution_interval_period = models.CharField(help_text='Choose day, week, month')
    execution_counter = models.IntegerField(default=9)
    date_last_execution = models.DateTimeField(default=datetime.now, blank=True)
    date_created = models.DateTimeField(auto_now_add=True)
