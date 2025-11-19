from django.db import models

# Create your models here.




class Scan(models.Model):
    id = models.PrimaryKey()
    scan_start = models.DateTimeField()
    scan_end = models.DateTimeField()
    duration = models.CharField()
    nmap_version = models.CharField(max_length=20)
    xml_version = models.CharField(max_length=20)
    arguments = models.CharField(max_length=800)
    count_live_hosts = models.IntegerField()
    scan_xml = models.
    scan_file = models.FileField()
    scan_hash = models.(help_text='MD5 hash of the XML file used for this scan record')
    notes = models.TextField()
    date_created =
    date_modified =



class Host(models.Model):
    id = models.PrimaryKey()
    hostname = models.CharField()
    hostname_type = models.CharField()
    ip_address = models.IP()
    mac_address = models.CharField(max_length=30)
    scan_id = models.ForeignKey()
    assessment_status = models.CharField()
    os_name = models.CharField()
    os_family = models.CharField()
    os_vendor = models.CharField()
    os_gen =
    os_type =
    state =
    state_reason =
    category = models.CharField()
    date_discovered = models.DateTimeField(auto_now=True)
    date_last_seen = models.DateTimeField(auto_now=True, help_text='Date last seen/scanned')
    count_scanned = models.SmallIntegerField(help_text='Number of times this host has been scanned')



class Service(models.Model):
    id = models.PrimaryKey
    port_number = models.IntegerField()
    port_proto = models.CharField()
    service_name = models.CharField()
    product_name = models.CharField()
    product_version = models.CharField()
    product_extrainfo = models.TextField(blank=True, default='')
    host_id = models.ForeignKey('Host')
    scan_id = models.ForeignKey('Scan')
    state = models.CharField()
    state_reason = models.CharField()
    category = models.CharField()
    attack_value = models.IntegerField()
    assessment_status = models.CharField()
    notes = models.TextField()


class Network(models.Model):
    id =
    network_cidr = models.
    date_created = models.DateTimeField()
    date_updated = models.DateTimeField(auto_now=True)
    sitecode = models.CharField(max_length=5)
    notes = models.TextField()


class ScanPolicy(models.Model):
    id =
    name = models.CharField(max_length=75)
    arguments = models.TextField()
    notes = models.TextField()


class ScanJob(models.Model):
    id =
    name = models.CharField(max_length=75)
    assigned_scan_id = models.ForeignKey('Scan', help_text='The original scan this job was created from to setup continuous scanning')
    assigned_policy = models.ForeignKey('ScanPolicy', help_text='The scan policy to use, if different from the original scan settings')
    execution_interval_numer = models.SmallIntegerField(help_text='Interval number for days/hours/etc.')
    execution_interval_period = models.CharField(help_text='Choose day, week, month')
    date_last_execution = models.DateTimeField()
    date_created = models.DateTimeField(auto_now_add=True)
    status = models.CharField(help_text='Is the job running, errored, enabled, or disabled')
    notes = models.TextField()

