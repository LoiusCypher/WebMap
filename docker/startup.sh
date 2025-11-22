#!/bin/bash
bash /opt/nmapdashboard/nmapreport/nmap/runcron.sh >> /tmp/log1 2>&1 &
python3 /opt/nmapdashboard/manage.py runserver 0:8000
