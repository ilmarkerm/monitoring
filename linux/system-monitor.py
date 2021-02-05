# Sending simple OS metrics to InfluxDB.
# Expected to be run as SystemD unit, with Restart=always
#
# If you don't like InfluxDB as a target, you just need to replace the following functions, everything else is generic:
# connect_influx
# write_influx
#
# Requires Python 3.6+
#
# Additional modules (everything else is standard in OEL7):
# pip3 install influxdb
# pip3 install python-dateutil
#
# 2021 Ilmar Kerm

# Example SystemD unit file:
# [Unit]
# Description=DBS system monitoring
# After=syslog.target network.target
# [Service]
# Nice=5
# Type=simple
# User={{ oracle_db_owner }}
# Group={{ oracle_db_group }}
# Restart=always
# RestartSec=5
# ExecStart=/bin/python3 /home/oracle/bin/system-monitor.py
# [Install]
# WantedBy=multi-user.target


import subprocess, os.path, os, re, syslog, socket, json, requests, signal
import dateutil.parser
from datetime import datetime, timedelta, timezone
from influxdb import InfluxDBClient
from influxdb.exceptions import InfluxDBClientError, InfluxDBServerError
from time import sleep
from threading  import Thread
from queue import Queue, Empty

###############
# CONFIGURATION
###############
# File for storing internal processing state
statefile = os.path.join('{{ monitoring_state_dir }}', 'system-monitor-state.json')
#
delay = timedelta(seconds=60)
max_runtime = timedelta(minutes=30)
# Log debug messages
debuglog = False

# InfluxDB connection details
influxconfig = {
    'host': "{{ monitoring_influx_env[monitoring_env]['host'] }}",
    'port': {{ influx_port }},
    'username': "{{ monitoring_influx_credentials[monitoring_env]['user'] }}",
    'password': "{{ monitoring_influx_credentials[monitoring_env]['password'] }}",
    'database': "{{ influx_db_host }}",
    'retention_policy': 'osmetrics'
}
# Tags added to every log record
common_tags = {
    'env': "{{ monitoring_tag_env }}",
    'market': "{{ monitoring_tag_market }}",
    'hostname_fqdn': socket.getfqdn(),
    'host_id': socket.gethostname(),
    'cluster_name': "{{ monitoring_tag_cluster }}",
    'is_virtual': "{{ 'True' if facter_is_virtual else 'False' }}"
}
# Openstack metadata URL
openstack_metadata_url = "{{ kc_metadata_url }}"

# Monitoring commands
maxruns = str(int(max_runtime.total_seconds()/delay.total_seconds())+1)
delay_str = str(int(delay.total_seconds()))
mon_process = {
    # Field/tag name is taken from regexp group name. First letter of the group name determins the data type:
    # t - tag (always string)
    # i - integer field
    # f - float field
    # anything else - string field
    #
    # group named "time" is special - this is the timestamp
    'host_cpu': {
        'cmd': ['/bin/mpstat', '-u', delay_str, maxruns],
        'regexp': re.compile(r'(?P<time>\d{2}\:\d{2}\:\d{2})\s+all\s+(?P<fuser>\d+\.\d+)\s+(?P<fnice>\d+\.\d+)\s+(?P<fsys>\d+\.\d+)\s+(?P<fiowait>\d+\.\d+)\s+(?P<firq>\d+\.\d+)\s+(?P<fsoft>\d+\.\d+)\s+(?P<fsteal>\d+\.\d+)\s+(?P<fguest>\d+\.\d+)\s+(?P<fgnice>\d+\.\d+)\s+(?P<fidle>\d+\.\d+)'),
        'ignorefirst': False
    },
    'host_vmstat': {
        'cmd': ['/bin/vmstat', '-nt', '-SM', delay_str, maxruns],
        'regexp': re.compile(r'(?P<iproc_runnable>\d+)\s+(?P<iproc_blocked>\d+)\s+(?P<imem_swpd>\d+)\s+(?P<imem_free>\d+)\s+(?P<imem_buff>\d+)\s+(?P<imem_cache>\d+)\s+(?P<iswap_si>\d+)\s+(?P<iswap_so>\d+)\s+(?P<iio_bi>\d+)\s+(?P<iio_bo>\d+).+(?P<time>\d{4}-\d{2}-\d{2} \d{2}\:\d{2}\:\d{2})'),
        'ignorefirst': True
    },
    'host_iostat': {
        'cmd': ['/usr/bin/iostat', '-dxmty', delay_str, maxruns],
        # Ignoring svctm - Warning! Do not trust this field any more.  This field will be removed in a future sysstat version. (from man page)
        'regexp': re.compile(r'^(?P<tdevice>[vd][\w\d-]+)\s+(?P<frrqms>\d+\.\d+)\s+(?P<fwrqms>\d+\.\d+)\s+(?P<frs>\d+\.\d+)\s+(?P<fws>\d+\.\d+)\s+(?P<frmbs>\d+\.\d+)\s+(?P<fwmbs>\d+\.\d+)\s+(?P<favgrqsz>\d+\.\d+)\s+(?P<favgqusz>\d+\.\d+)\s+(?P<fawait>\d+\.\d+)\s+(?P<frawait>\d+\.\d+)\s+(?P<fwawait>\d+\.\d+)\s+\d+\.\d+\s+(?P<futil>\d+\.\d+)'),
        'timeregexp': re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}\:\d{2}\:\d{2})$'),
        'ignorefirst': False
    },
    'host_df': {
        'cmd': ['/bin/bash', '-c', "while true; do date -uIs ; df -TPBM ; sleep 5m; done"],
        'regexp': re.compile(r'(?P<tfilesystem>.+)\s+(?P<ttype>[\w\d]+)\s+(?P<itotal_mb>\d+)M\s+(?P<iused_mb>\d+)M\s+(?P<iavailable_mb>\d+)M\s+(?P<iuse_pct>\d+)\%\s+(?P<tmount>.+)$'),
        'timeregexp': re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}\:\d{2}\:\d{2}\+0000)$'),
        'ignorefirst': False
    },
    'host_net': {
        #'cmd': ['/bin/bash', '-c', f"while true; do date -uIs ; /usr/sbin/ip -s -o link ; sleep {delay_str}; done"],
        'cmd': ['/bin/bash', '-c', "while true; do date -uIs ; /usr/sbin/ip -s -o link ; sleep 5m; done"],
        'check': ['/bin/ls','/usr/sbin/ip'],
        'regexp': re.compile(r'\d+\:\s+(?P<tdevice>[\w\d@]+)\:.+mtu (?P<imtu>[\d]+) .+\sRX\:.+ \\\s+(?P<irx_bytes>\d+)\s+(?P<irx_packets>\d+)\s+(?P<irx_errors>\d+)\s+(?P<irx_dropped>\d+)\s+(?P<irx_overrun>\d+)\s+(?P<irx_mcast>\d+)\s+\\\s+TX\:.+\\\s+(?P<itx_bytes>\d+)\s+(?P<itx_packets>\d+)\s+(?P<itx_errors>\d+)\s+(?P<itx_dropped>\d+)\s+(?P<itx_carrier>\d+)\s+(?P<itx_collsns>\d+)'),
        'timeregexp': re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}\:\d{2}\:\d{2}\+0000)$'),
        'ignorefirst': False
    },
    'host_tcp': {
        'cmd': ['/bin/bash', '-c', "while true; do date -uIs ; /usr/sbin/nstat -as TcpRetransSegs ; sleep 5m; done"],
        'check': ['/bin/ls','/usr/sbin/nstat'],
        'regexp': re.compile(r'TcpRetransSegs\s+(?P<itcpretranssegs>\d+)\s'),
        'timeregexp': re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}\:\d{2}\:\d{2}\+0000)$'),
        'ignorefirst': False
    },
    'host_memory': {
        'cmd': ['/bin/free', '-mw', '-s', delay_str, '-c', maxruns],
        'regexp': re.compile(r'Mem\:\s+(?P<itotal>\d+)\s+(?P<iused>\d+)\s+(?P<ifree>\d+)\s+(?P<ishared>\d+)\s+(?P<ibuffers>\d+)\s+(?P<icache>\d+)\s+(?P<iavailable>\d+)'),
        'ignorefirst': False
    },
    'host_pressure': {
        # PSI needs to be enabled by adding psi=1 to kernel boot command line
        'cmd': ['/bin/bash', '-c', "while true; do date -uIs ; cat /proc/pressure/cpu | sed 's/^/cpu /' ; cat /proc/pressure/memory | sed 's/^/memory /' ; cat /proc/pressure/io | sed 's/^/io /'; sleep 1m; done"],
        'check': ['/bin/cat','/proc/pressure/cpu'],
        'regexp': re.compile(r'(?P<tresource>[a-z]+)\s+(?P<tmetric>[a-z]+)\s+avg10=(?P<favg10>\d+\.\d+)\s+avg60=(?P<favg60>\d+\.\d+)\s+avg300=(?P<favg300>\d+\.\d+)\s+total=(?P<itotal>\d+)'),
        'timeregexp': re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}\:\d{2}\:\d{2}\+0000)$'),
        'ignorefirst': False
    },
    'host_mount': {
        'cmd': ['/bin/bash', '-c', "while true; do date -uIs ; systemctl --no-pager --no-legend -t mount list-units ; sleep 5m; done"],
        'regexp': re.compile(r'(?P<tunit>[\w\-_]+\.mount)\s+(?P<tload>[a-z]+)\s+(?P<tactive>[a-z]+)\s+(?P<tsub>[a-z]+)\s+(?P<description>.+)'),
        'timeregexp': re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}\:\d{2}\:\d{2}\+0000)$'),
        'ignorefirst': False
    },
    'host_packages': {
        'cmd': ['/usr/bin/yum', 'updateinfo'],
        'regexp': re.compile(r'^\s+(?P<iupdate_count>\d+)\s+(?P<tupdate_classification>.+)'),
        'ignorefirst': False
    }
}

############
# END CONFIG
############

def log(msg, debugmsg=True):
    global debuglog
    if not debugmsg or debuglog:
        # What to do with the log output, by default log is sent to syslog
        syslog.syslog(msg)
        #print(msg)

def connect_influx():
    global influxconfig
    inf = InfluxDBClient(
        host = influxconfig['host'],
        port = influxconfig['port'],
        ssl = True, 
        verify_ssl = True, 
        gzip = True,
        username = influxconfig['username'],
        password = influxconfig['password']
    )
    inf.switch_database(influxconfig['database'])
    return inf

def write_influx():
    # Pushes the point queue to influx
    global state, inf, influxconfig
    if '.queue' not in state or len(state['.queue']) == 0:
        return
    log(f"Pushing queue to influx. Queue size: {len(state.get('.queue', []))}")
    try:
        inf.write_points(
            points=state['.queue'],
            time_precision='n',
            retention_policy=influxconfig['retention_policy'],
            batch_size=3000)
        state['.queue'] = []
    except InfluxDBClientError as e:
        # Client side error (invalid message?)
        log(f"Client error writing points to InfluxDB: {e}", False)
        state['.queue'] = []
    except InfluxDBServerError as e:
        # Server error
        log(f"Influx server error writing points: {e}", False)

def write_state():
    # Persists existing log reading state (and unsent queue) to disk, so next time program starts it will just continue where it left off
    global state, statefile
    write_influx()
    with open(statefile, 'w') as sf:
        json.dump(state, sf)

def str_to_datetime(s):
    try:
        # Try parsing the input string into datetime
        time = dateutil.parser.parse(s)
    except:
        # There was an exception parsing the string as time
        return None
    if time.tzinfo is None:
        time = time.replace(tzinfo=timezone.utc)
    if (time-timedelta(minutes=1)) > datetime.now(tz=timezone.utc):
        # Something is wrong with the timestamp, lets just reset it
        return None
    return time

def timestamp_ns(dt):
    # Converts timestamp to timestamp in ns
    return int(dt.timestamp()*10**9)

def process_line(line, process_object):
    global state
    ls = line.strip()
    # Try processing line as a metrics line
    m = process_object['regexp'].search(ls)
    if m:
        # Ignore the first match, since some programs output the global stats (since startup) first
        if process_object.get('ignorefirst', False):
            process_object['ignorefirst'] = False
            return
        # Line matched with regular expression
        values = m.groupdict()
        # Timestamp calculation
        time = None
        if 'time' in values:
            time = str_to_datetime(values.pop('time'))
        # If there was no timestamp provided in the line
        if time is None:
            if process_object.get('timestamp', None) is not None:
                # Set the last remembered timestamp
                time = process_object['timestamp']
            else:
                # Set timestamp as current time
                time = datetime.now(tz=timezone.utc)
        #
        record = {
            'time': timestamp_ns(time),
            'measurement': program,
            'tags': common_tags.copy(),
            'fields': {
                'value': 1
            }
        }
        for key in values:
            if key.startswith('t'):
                record['tags'][key[1:]] = values[key]
            elif key.startswith('f'):
                floatval = float(values[key])
                # InfluxDB python client seems to be writing 0.0 as a string??
                #if not floatval:
                #    floatval = 0.000000001
                record['fields'][key[1:]] = floatval
            elif key.startswith('i'):
                record['fields'][key[1:]] = int(values[key])
            else:
                record['fields'][key] = values[key]
        #
        state['.queue'].append(record)
    # Check if this line could be a timestamp
    elif 'timeregexp' in process_object:
        m = process_object['timeregexp'].search(ls)
        if m:
            process_object['timestamp'] = str_to_datetime(m.group(0))
            return

def enqueue_output(out, queue, p):
    for line in iter(out.readline, ''):
        queue.put(line)

def openstack_metadata(metadata_url):
    # Call openstack metadata URL to fetch some additional tags
    try:
        host_meta_response = requests.get(metadata_url, timeout=2)
        if host_meta_response.status_code != 200:
            log(f"Invalid status code from KC metadata query: {host_meta_response.status_code}", False)
            return {}
        host_meta = host_meta_response.json()
        return {
            'openstack_az': host_meta.get('availability_zone', None),
            'openstack_region': host_meta.get('region', None),
            'openstack_project_id': host_meta.get('project_id', None),
            'openstack_owner': host_meta.get('meta', {}).get('owner', None)
        }
    except:
        return {}

def signal_handler(signum, frame):
    global termination_signal_received
    termination_signal_received = True
    log("Termination signal received")

######
# MAIN
######
start_time = datetime.utcnow()
inf = connect_influx()
# Register signal handler
termination_signal_received = False
ign = signal.signal(signal.SIGTERM, signal_handler)
ign = signal.signal(signal.SIGINT, signal_handler)

# Initialise state
state = {}
if os.path.isfile(statefile):
    try:
        with open(statefile, 'r') as sf:
            state = json.load(sf)
    except:
        pass
if '.queue' not in state:
    state['.queue'] = []

# Check if all needed programs exist
# If not, remove this check
for program in mon_process.copy():
    binaryname = mon_process[program]['cmd'][0]
    if not os.path.exists(binaryname):
        log(f"Program {binaryname} not found", False)
        del mon_process[program]
        continue
    # Try executing the check command
    if 'check' in mon_process[program]:
        check_proc = subprocess.run(mon_process[program]['check'], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if check_proc.returncode != 0:
            log(f"Pre-check execution failed for {program}", False)
            del mon_process[program]
if not len(mon_process.keys()):
    raise Exception("Nothing to monitor")

# Start monitoring programs
for program in mon_process:
    log(f"Starting {program}: {' '.join(mon_process[program]['cmd'])}", False)
    # LC_TIME=en_DK seems to be the only way to get proper ISO formatted timestamps
    mon_process[program]['p'] = subprocess.Popen(args=mon_process[program]['cmd'], bufsize=1, universal_newlines=True, shell=False, stdout=subprocess.PIPE, env={'LC_TIME': 'en_DK','TZ': 'UTC'}, encoding='ascii')
    mon_process[program]['finished'] = False

# Starting threads (for non-blocking p.stdout.readline() and some programs may output different number of lines per iteration)
log("Starting output reading threads", False)
for program in mon_process:
    mon_process[program]['q'] = Queue()
    mon_process[program]['t'] = Thread(target=enqueue_output, args=(mon_process[program]['p'].stdout, mon_process[program]['q'], mon_process[program]['p']), daemon=True)
    mon_process[program]['t'].start()

# Since after startup the monitoring programs will wait for the first interval, then good time to issue OpenStack metadata query, that can take a few seconds
common_tags.update(openstack_metadata(openstack_metadata_url))

# Data gathering and processing
log("Start data gathering", False)
while True:
    # Read all queued lines from all programs
    for program in mon_process:
        if mon_process[program]['finished']:
            continue
        while True:
            try:
                line = mon_process[program]['q'].get_nowait()
            except Empty:
                break
            else:
                process_line(line, mon_process[program])
        # Check if program is still alive
        if mon_process[program]['p'].poll() is not None:
            mon_process[program]['finished'] = True
            # Check if program exited prematurely with an error
            if mon_process[program]['p'].returncode > 0:
                log(f"{program} has finished with exit code {mon_process[program]['p'].returncode}", False)
                errtags = common_tags.copy()
                errtags.update({
                    'program': program,
                    'error_type': 'non_zero_exit_code'
                })
                state['.queue'].append({
                    'time': timestamp_ns(datetime.now(tz=timezone.utc)),
                    'measurement': 'monitoring_error',
                    'tags': errtags,
                    'fields': {
                        'exitcode': mon_process[program]['p'].returncode
                    }
                })
    #
    if state['.queue']:
        write_state()
    # Implement maximum program runtime
    if datetime.utcnow() - start_time > max_runtime:
        log("Time limit reached, exiting")
        break
    else:
        for sleepcount in range(int(delay.total_seconds())):
            if termination_signal_received:
                break
            sleep(1)
    if termination_signal_received:
        break


# End monitoring programs if they are still running
log("Terminating monitoring programs", False)
for program in mon_process:
    if not mon_process[program]['finished'] and mon_process[program]['p'].poll() is None:
        mon_process[program]['p'].terminate()

# All done - drop queue if it is too big and write state
if len(state.get('.queue', [])) > 1000:
    state['.queue'] = []
write_state()
