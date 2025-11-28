#!/bin/bash
ls -al '/opt/nmapdashboard/db.sqlite3'
python3 /opt/nmapdashboard/manage.py makemigrations
python3 /opt/nmapdashboard/manage.py migrate --run-syncdb
sqlite3 '/opt/nmapdashboard/db.sqlite3' ".tables '%';"
sqlite3 '/opt/nmapdashboard/db.sqlite3' "SELECT * FROM nmapreport_scanjob;"
bash /opt/nmapdashboard/nmapreport/runcron.sh & # > /dev/null 2>&1 &
python3 /opt/nmapdashboard/manage.py runserver 0:8000
