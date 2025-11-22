from django.conf import settings
import os, re, json, time

cdir = os.path.dirname(os.path.realpath(__file__))

schedfiles = os.listdir('/opt/schedule/')

def gethours(f):
	return {
		'1h': 3600,
		'1d': 86400,
		'1w': 604800,
		'1m': 2592000
	}[f]

nextsched=time.time()+gethours('1m')
for i in schedfiles:
	if re.search(r'^[a-f0-9]{32,32}\.json$', i.strip()) is not None:
		sched = json.loads(open('/opt/schedule/'+i, "r").read())
		
		nextrun = (sched['lastrun'] + gethours(sched['params']['frequency']))
		if nextrun <= time.time():
			sched['number'] = (sched['number']+1)
			print("[RUN]   scan:"+sched['params']['filename']+" id:"+str(sched['number'])+" (nextrun:"+str(nextrun)+" / now:"+str(time.time())+")")

			sched['lastrun'] = time.time()
			nextrun = (sched['lastrun'] + gethours(sched['params']['frequency']))

			nmap_tmp_file = '/tmp/'+str(sched['number'])+'_'+sched['params']['filename']+'.active'
			nmap_out_file = '/opt/xml/webmapsched_'+str(sched['lastrun'])+'_'+sched['params']['filename']
			nmapout = os.popen('nmap '+sched['params']['params']+' --script='+cdir+'/nse/ -oX '+nmap_tmp_file+' '+sched['params']['target']+' > /dev/null '
			' ; sleep 5 && mv '+nmap_tmp_file+' '+nmap_out_file+' && python3 '+cdir+'/cve.py '+nmap_out_file+'').readlines()

			print('file: '+nmap_tmp_file)
			print(nmapout)

			f = open('/opt/schedule/'+i, "w")
			f.write(json.dumps(sched, indent=4))

			time.sleep(10)
		else:
			print("[SKIP]  scan:"+sched['params']['filename']+" id:"+str(sched['number'])+" (nextrun:"+str(nextrun)+" / now:"+str(time.time())+")")
		nextsched=min(nextsched,nextrun)
	print("[DEBUG] nextsched:"+str(nextsched - time.time()))

