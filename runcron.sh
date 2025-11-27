#!/bin/bash
sleep 20
while true; do
	echo "[SLEEP] for a while..."
	sleep 10
	python3 /opt/nmapdashboard/manage.py cron
done
