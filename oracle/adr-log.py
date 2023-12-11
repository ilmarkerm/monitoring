# This script read all recently changed ADR XML log files and sends them to InfluxDB
# Expected to be run as SystemD unit, with Restart=always
# It needs to exit and restart regularly, since it keeps the logfiles open for reading and it would not detect that oracle has rotated the logfile otherwise. Not a bug, done it this way on purpose.
#
# Primary goal: Pushed out from automation (Ansible) to all Oracle servers and started as a service, it figures out itself what log files to monitor without any intervention
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
# 2020 Ilmar Kerm

# Example SystemD unit file:
#
# [Unit]
# Description=ADR Log monitoring
# After=syslog.target network.target
# [Service]
# Nice=5
# Type=simple
# User={{ oracle_db_owner }}
# Group={{ oracle_db_group }}
# Restart=always
# RestartSec=30
# ExecStart=/bin/python3 /home/oracle/bin/adr-log.py
# [Install]
# WantedBy=multi-user.target

import subprocess, os.path, os, json, re, syslog, socket, requests, signal
import dateutil.parser
from datetime import datetime, timedelta, timezone
from lxml import etree
from influxdb import InfluxDBClient
from influxdb.exceptions import InfluxDBClientError, InfluxDBServerError
from time import sleep


###############
# CONFIGURATION
###############
# Here you specify the ADR base directories that need to be searched, as a list
input_adr_paths = [{% for adrpath in adr_base %}'{{ adrpath }}'{% if not loop.last %},{% endif %}{% endfor %}]
# File for storing internal processing state
statefile = os.path.join('{{ monitoring_state_dir }}', 'adr-log-state.json')
# Maximum program runtime
# Sleeping time between each log gathering run
max_runtime = timedelta(minutes=10)
sleeptime = timedelta(seconds=30)
# Log debug messages
debuglog = False

# InfluxDB connection details
influxconfig = {
    'host': "{{ monitoring_influx_env[monitoring_env]['host'] }}",
    'port': {{ influx_port }},
    'username': "{{ monitoring_influx_credentials[monitoring_env]['user'] }}",
    'password': "{{ monitoring_influx_credentials[monitoring_env]['password'] }}",
    'database': "{{ influx_db }}",
    'retention_policy': 'short'
}
# Tags added to every log record
common_tags = {
    'hostname_fqdn': socket.getfqdn(),
    'env': "{{ monitoring_tag_env }}",
    'market': "{{ monitoring_tag_market }}"
}
# Openstack metadata URL
openstack_metadata_url = "{{ kc_metadata_url }}"

# Regular expressions for parsing log text
# Add here new rules if you want to match log text to some pattern
# Matched rule name will be stored in tag rule_match
# Use named groups to fetch values, then matched values will be stored in tag with the same name
# Order matters, first match will stop processing
# If group name first character is f then it is written as field (and first character stripped), otherwise it is written as tag
regparse = {
    # First level is comp_id from log record
    #
    # Field/tag name is taken from regexp group name. First letter of the group name determins the data type:
    # t - tag (always string)
    # i - integer field
    # f - float field
    # anything else - string field
    'tnslsnr': {
        # Rule name and the regular expression
        'tns_service_action': re.compile(r'(?P<taction>service_\w+) \* (?P<tinstance>\w+) \* (?P<treturncode>\d+)$'),
        'tns_short': re.compile(r'\(.+\) \* (?P<tevent>\w+) \* (?P<treturncode>\d+)$'),
        'tns_error': re.compile(r'^[\w\-:\s]+ \* (?P<ttnserror>\d+)$'),
        'tns_long': re.compile(r'\(.+PROTOCOL=(?P<tprotocol>\w+).+HOST=(?P<tclienthost>[\d\.]+).+\) \* (?P<tevent>\w+) \* (?P<tservice>[\w\.]+) \* (?P<treturncode>\d+)$')
    },
    'rdbms': {
        'rdbms_ora20': re.compile(r"ORA-00020\:.+\((?P<iprocesslimit>\d+)\)"),
        'rdbms_fra_full': re.compile(r"ORA-19809\:"),
        'rdbms_terminating_hung': re.compile(r"Terminating process hung on an operation"),
        'rdbms_hung_io': re.compile(r"Process .+ hung on an I/O after"),
        'rdbms_swapping': re.compile(r"Heavy swapping observed on system"),
        'rdbms_primary_isolated': re.compile(r"ORA-16830\:"),
        'rdbms_lost_write': re.compile(r"ORA-00742\:"),
        'rdbms_user_failover': re.compile(r"A user-configurable Fast-Start Failover condition was detected\. The primary is shutting down due to (?P<reason>.+)\."),
        'rdbms_ora1555': re.compile(r"ORA-01555.+SQL ID: (?P<sqlid>[a-z0-9]+).+Query Duration=(?P<iduration>[a-z0-9]+) sec")
    },
    'crs': {
        'crs_node_down': re.compile(r"Node down event .+ '(?P<ttargetnode>.+)'"),
        'crs_network_missing': re.compile(r"Network communication with node (?P<ttargetnode>.+) \(.+ missing for (?P<itimeoutpct>\d+)%"),
        'crs_cvu_setup_error': re.compile(r"CVU found following errors with Clusterware setup : (?P<cvuerror>.+).$"),
        'crs_this_node_evicted': re.compile(r"CRS-1608\:.+evicted by node (?P<ievictedbynum>\d+), (?P<evictedbynode>.+); details"),
        'crs_other_node_evicted': re.compile(r"CRS-1607\: Node (?P<ttargetnode>.+) is being evicted")
    }
}
############
# END CONFIG
############

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

def log(msg, debugmsg=True):
    global debuglog
    if not debugmsg or debuglog:
        # What to do with the log output, by default log is sent to syslog
        syslog.syslog(msg)
        #print(msg)

def get_adr_base(input_adr_paths):
    # Check that each directory actually exists
    adr_base = []
    for d in input_adr_paths:
        if os.path.isdir(d):
            adr_base.append(d)
    return adr_base

def find_log_files():
    global adr_base
    if not adr_base:
        return []
    # Execute find to find all alert/log.xml files that have been recently modified
    #find p1 p2 -path '*/alert/log.xml' -mmin -40
    logfiles = []
    log("Searching for recently changed logfiles", False)
    p = subprocess.run(['find']+adr_base+['-path','*/alert/log.xml','-mmin','-40','-readable'], shell=False, timeout=20, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, encoding='ascii')
    if p.stdout is not None and p.stdout:
        for line in p.stdout.splitlines():
            if os.path.isfile(line):
                logfiles.append(line)
                log(f"Found logfile: {line}", False)
    return logfiles

def get_cluster_name():
    # Returns Oracle cluster name, if the host is part of a cluster
    # Location of clusterware home can be either supplied with CRS_HOME environment variable or it will execute script /home/oracle/bin/getcrshome.sh that returns CRS home path
    try:
        crshome = None
        if 'CRS_HOME' not in os.environ:
            crshomescript = '/home/oracle/bin/getcrshome.sh'
            if os.path.isfile(crshomescript):
                p = subprocess.run([crshomescript], shell=False, timeout=5, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, encoding='ascii')
                if p.returncode == 0 and p.stdout:
                    crshome = p.stdout.strip()
        else:
            crshome = os.environ['CRS_HOME']
        if crshome is not None and crshome:
            p = subprocess.run([f"{crshome}/bin/cemutlo",'-n'], shell=False, timeout=5, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, encoding='ascii')
            if p.returncode == 0:
                return p.stdout.strip()
        return '- none -'
    except:
        return '- none -'

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

def timestamp_ns(dt):
    # Converts timestamp to timestamp in ns
    return int(dt.timestamp()*10**9)

def fix_field_value(v):
    # Just some string fixing
    if isinstance(v, str):
        return v.replace("\n", " ").replace("\t", " ")
    else:
        return v

def process_record(data, loginfo):
    # Parses the XML message into Influx dict
    global common_tags, state, regparse
    tag_attrib = ['comp_id','type','group','host_id','host_addr','module','con_uid','con_name','level','prob_key','downstream_comp']
    ignore_attrib = ['org_id']
    if '.queue' not in state:
        state['.queue'] = []
    try:
        msg = etree.fromstring(data)
        #log(msg.attrib)
        msgtime = timestamp_ns(dateutil.parser.isoparse(msg.attrib.pop('time')))
        if msgtime <= state[loginfo['fullpath']]['time']:
            # We have already progressed past this timestamp
            return
        if 'comp_id' not in msg.attrib:
            # Must be invalid record, since comp_id attribute is missing
            log(f"Skipping record, since comp_id attribute is missing. Input data: {data}")
            return
        record = {
            'time': msgtime,
            'tags': loginfo.copy(),
            'fields': {
                'value': 1 # This is just a dummy field, since InfluxDB requires at least one field in every record
            }
        }
        record['tags'].update(common_tags)
        for tag in msg.attrib:
            if tag == 'level':
                # Translate "level" number into a string
                if msg.attrib[tag] in ['1','2','8','16']:
                    record['tags']['level_str'] = {
                        '1': 'CRITICAL',
                        '2': 'SEVERE',
                        '8': 'IMPORTANT',
                        '16': 'NORMAL'
                    }[msg.attrib[tag]]
                record['tags'][tag] = msg.attrib[tag]
            elif tag in tag_attrib:
                # Set attribute as tag
                record['tags'][tag] = msg.attrib[tag]
            elif tag not in ignore_attrib:
                # Set attribute as field
                record['fields'][tag] = msg.attrib[tag]
        record['measurement'] = f"alert_{record['tags']['comp_id']}"
        # Reading message text
        # There could be multiple <txt> elements under one <msg>
        txtrecords = []
        for child in msg:
            if child.tag == 'txt':
                txtrecords.append(fix_field_value(child.text.strip()))
        if txtrecords:
            record['fields']['txt'] = "; ".join(txtrecords)
        # Parsing txt field with regular expressions
        if record['tags']['comp_id'] in regparse.keys() and 'txt' in record['fields']:
            for searchkey in regparse[record['tags']['comp_id']]:
                m = regparse[record['tags']['comp_id']][searchkey].search(record['fields']['txt'])
                if m:
                    for grouptag, groupval in m.groupdict().items():
                        # Check how to write the group, as tag or as field
                        keyname = grouptag[1:]
                        if grouptag.startswith('t'):
                            record['tags'][keyname] = groupval
                        elif grouptag.startswith('i'):
                            record['fields'][keyname] = int(groupval)
                        elif grouptag.startswith('f'):
                            record['fields'][keyname] = float(groupval)
                        else:
                            record['fields'][grouptag] = groupval
                    record['tags']['rule_match'] = searchkey
                    break
        #
        state['.queue'].append(record)
        # Advance timestamp in state
        state[loginfo['fullpath']]['time'] = msgtime
    except Exception as e:
        log(f"Failed to process: {data}", False)
        log(f"Exception: {e}", False)
        #raise

def process_logfile(filename):
    # Opens logfile and reads records from it, incrementally
    global state, open_logfiles, adr_base
    log(f"Processing log: {filename}")
    # Parse some information about logfile
    loginfo = {'fullpath': filename}
    for basepath in adr_base:
        if filename.startswith(basepath):
            loginfo['relpath'] = os.path.relpath(filename, start=basepath)
            splits = loginfo['relpath'].split('/')
            loginfo['comp_level_1'] = splits[1]
            loginfo['comp_level_2'] = splits[2]
    #
    if (filename not in open_logfiles.keys() or open_logfiles[filename].closed):
        if not os.path.isfile(filename):
            log(f"File does not exist: {filename}", False)
            return
        # Open logfile for reading
        inode = os.stat(filename).st_ino
        log(f"Opening logfile, inode: {inode}")
        open_logfiles[filename] = open(filename, 'r')
        # Assuming file inode changes when oracle recreates it (and rotates old file to a new name)
        if filename not in state.keys() or inode != state[filename].get('inode', -1):
            state[filename] = {
                'inode': inode,
                'seek': 0,
                'time': timestamp_ns(datetime.now(tz=timezone.utc)-timedelta(days=2))
            }
    else:
        log("Continuing with already open logfile")
    # Seek to record start
    open_logfiles[filename].seek(state[filename]['seek'])
    # https://stackoverflow.com/questions/49785865/meaning-of-oserror-telling-position-disabled-by-next-call-error?noredirect=1&lq=1
    current_record = ""
    num_messages = 0
    while True:
        try:
            line = open_logfiles[filename].readline()
        except Exception as e:
            # Unicode decoding error may happen
            log(f"Exception when reading file: {e}", False)
            state[filename]['seek'] = open_logfiles[filename].tell()
            break
        if not line:
            # File has reached its end
            break
        current_record+= line
        if "</msg>" in line:
            num_messages += 1
            process_record(current_record, loginfo)
            current_record = ""
            state[filename]['seek'] = open_logfiles[filename].tell()
            #break
    log(f"Messages read: {num_messages}")

def signal_handler(signum, frame):
    global termination_signal_received
    termination_signal_received = True
    log("Termination signal received")

######
# MAIN
######

start_time = datetime.utcnow()
inf = connect_influx()
open_logfiles = {}
# Register signal handler
termination_signal_received = False
ign = signal.signal(signal.SIGTERM, signal_handler)
ign = signal.signal(signal.SIGINT, signal_handler)

# Find logfiles to process
adr_base = get_adr_base(input_adr_paths)
logfiles = find_log_files()

# Read current file processing state
state = {}
if os.path.isfile(statefile):
    with open(statefile, 'r') as sf:
        state = json.load(sf)

# Add cluster_name to common tags
common_tags.update({
    'cluster_name': get_cluster_name()
})
# Add openstack metadata to common tags
common_tags.update(openstack_metadata(openstack_metadata_url))

# Loop through all logfiles
log("Start scanning logfiles", False)
while True:
    for lf in logfiles:
        process_logfile(lf)
    write_state()
    # Implement maximum program runtime
    if datetime.utcnow() - start_time > max_runtime:
        log("Time limit reached, exiting", False)
        break
    else:
        for sleepcount in range(int(sleeptime.total_seconds())):
            if termination_signal_received:
                break
            sleep(1)
    if termination_signal_received:
        break

# All done - close files; if unsent message queue is too big, drop it; write state
if len(state.get('.queue', [])) > 1000:
    state['.queue'] = []
write_state()
for f in open_logfiles:
    if not open_logfiles[f].closed:
        open_logfiles[f].close()
