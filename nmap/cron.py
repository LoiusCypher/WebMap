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

for i in schedfiles:
	if re.search(r'^[a-f0-9]{32,32}\.json$', i.strip()) is not None:
		sched = json.loads(open('/opt/schedule/'+i, "r").read())
		
		nextrun = (sched['lastrun'] + gethours(sched['params']['frequency']))
		if nextrun <= time.time():
			sched['number'] = (sched['number']+1)
			print("[RUN]   scan:"+sched['params']['filename']+" id:"+str(sched['number'])+" (nextrun:"+str(nextrun)+" / now:"+str(time.time())+")")

			sched['lastrun'] = time.time()

			nmapout_file = '/tmp/'+str(sched['number'])+'_'+sched['params']['filename']
			nmapout_cmd = 'nmap '+sched['params']['params']+' --script='+cdir+'/nse/ -oX '+nmapout_file+'.active '+sched['params']['target']+' > /dev/null 2>&1 && '
			nmapout_cmd = nmapout_cmd+'sleep 5 && mv '+nmapout_file+'.active /opt/xml/webmapsched_'+str(sched['lastrun'])+'_'+sched['params']['filename']
			nmapout_cmd = nmapout_cmd+' && python3 '+cdir+'/cve.py webmapsched_'+str(sched['lastrun'])+'_'+sched['params']['filename']+''

			nmapout = os.popen('nmap '+sched['params']['params']+' --script='+nmapout_file+'.active '+sched['params']['target']+
			' && sleep 5 && mv '+nmapout_file+'.active /opt/xml/webmapsched_'+str(sched['lastrun'])+'_'+sched['params']['filename']+
			' && python3 '+cdir+'/cve.py webmapsched_'+str(sched['lastrun'])+'_'+sched['params']['filename']+'').readlines()

			print('file: '+nmapout_file)
			print('cmd: '+nmapout_cmd)
			print(nmapout)

			f = open('/opt/schedule/'+i, "w")
			f.write(json.dumps(sched, indent=4))

			time.sleep(10)
		else:
			print("[DEBUG] nextrun:"+str(nextrun - time.time()))
			print("[SKIP]  scan:"+sched['params']['filename']+" id:"+str(sched['number'])+" (nextrun:"+str(nextrun)+" / now:"+str(time.time())+")")

