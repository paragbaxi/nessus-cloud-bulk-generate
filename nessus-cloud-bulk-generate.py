#!/usr/bin/env python
"""
Usage: %(scriptName)s

Supports:
* Multiple .nessus file inputs
* Randomize IP assignments
* Track credentialed scans

Considering (if requested):
* Custom scan start time
* MAC addresses
* Private / Public address spacing: import private IPs as private IPs, and public IPs as public IPs
* DNS names
"""


import argparse
import ipaddress
import re
import datetime
import random
import string
import mmap
from sys import getsizeof

from lxml import etree, objectify
from random import shuffle

# logging
import logging, logging.config, os, sys

# pip install git+https://github.com/niltonvolpato/python-progressbar.git
from progressbar import AdaptiveETA, Bar, Percentage, ProgressBar

import requests, json
from requests_toolbelt.multipart.encoder import MultipartEncoder
import configparser


def import_nessus_file(nessusFile):
    """Import .nessus file."""
    root = objectify.parse(nessusFile).getroot()
    # # Grab policy values.
    # plugins = set(str(root.Policy.Preferences.ServerPreferences.preference.value)[:-1].split(';'))
    # data is the nessus vuln data that we will populate blank hosts with.
    data = []
    for h in root.Report.ReportHost:
        # Get IP address.
        ipAddress = h.get('name')
        logging.debug('IP address = %s' % ipAddress)
        # Public or private IP address space (RFC 1918)?
        isPrivateAddressSpace = ipaddress.ip_address(
            ipAddress).is_private
        logging.debug('isPrivateAddressSpace = %s' %
                      str(isPrivateAddressSpace))
        # Store scan duration in seconds.
        scanStart = datetime.datetime.strptime(
            h.HostProperties.xpath(
                '/descendant::tag[@name="HOST_START"][1]')[0].text,
            '%c')
        scanEnd = datetime.datetime.strptime(
            h.HostProperties.xpath(
                '/descendant::tag[@name="HOST_END"][1]')[0].text,
            '%c')
        scanDuration = (scanEnd - scanStart).seconds
        logging.debug('isPrivateAddressSpace = %s' %
                      str(isPrivateAddressSpace))
        # Save host + host attributes
        host = {'isPrivateAddressSpace': isPrivateAddressSpace,
                'scanDuration': scanDuration,
                'hostXml': h}
        data.append(host)
    # Data consist all host+vuln data from imported nessus file, each item is a
    # host.
    # return (data, plugins)
    return data

    # elems = [el for el in root.Report.iterchildren()]
    # # data is the nessus vuln data that we will populate blank hosts with.
    # data = []
    # isPrivateAddressSpace = 'false'
    # hostDetails = None
    # plugins = b''
    # pluginsCount = 0
    # firstHost = True
    # for elem in elems:
    #     if elem.tag == 'ReportHost':
    #         # New host
    #         logging.debug('IP address = %s' % elem.get('name'))
    #         # Public or private IP address space? (RFC 1918)
    #         isPrivateAddressSpace = ipaddress.ip_address(
    #             elem.get('name')).is_private
    #         logging.debug('isPrivateAddressSpace = %s' %
    #                       str(isPrivateAddressSpace))
    #         # Store scan duration in seconds
    #         scanStart = datetime.datetime.strptime(ipaddress.ip_address(
    #             elem.get('name')).HOST_START, '%c')
    #         scanEnd = datetime.datetime.strptime(ipaddress.ip_address(
    #             elem.get('name')).HOST_END, '%c')
    #         scanDuration = (scanEnd - scanStart).seconds
    #         logging.debug('isPrivateAddressSpace = %s' %
    #                       str(isPrivateAddressSpace))
    #         # Skip if first host, need to grab plugins data.
    #         logging.debug(firstHost)
    #         if firstHost == True:
    #             # Don't skip again, in case first host has no plugins.
    #             firstHost = False
    #             continue
    #         # Save plugins.
    #         host = {'plugins': plugins,
    #                 'isPrivateAddressSpace': isPrivateAddressSpace,
    #                 'duration': scanDuration,
    #                 'hostXml': elem}
    #         data.append(host)
    #         logging.debug('pluginsCount = %s' % str(pluginsCount))
    #         # Start new plugins for new host.
    #         plugins = b''
    #         pluginsCount = 0
    #         continue
    #     else:
    #         # Plugin data.
    #         plugins += etree.tostring(elem)
    #         pluginsCount += 1
    # # Save last ReportHost
    # host = {'plugins': plugins,
    #         'isPrivateAddressSpace': isPrivateAddressSpace,
    #         'duration': scanDuration,
    #         'hostXml': elem}
    # data.append(host)
    # logging.debug('pluginsCount = %s' % str(pluginsCount))
    # Data consist all vuln data from imported nessus file, each item is a
    # host.
    # return data


def fake_mac_addresses(count, random=False):
    """Return a list of COUNT fake mac addresses from 00:00:00:00:00:00 to 00:00:00:ff:ff:ff."""
    macs = []
    mac = '00:00:00:'
    # for number in range(16**6):
    for number in range(count):
        hex_num = hex(number)[2:].zfill(6)
        macs.append("{}{}{}:{}{}:{}{}".format(mac, *hex_num))
    # Randomize if requested.
    if random:
        shuffle(macs)
    return macs


def fake_ip_addresses(count, random=False):
    """Return a list of COUNT fake IP addresses from 10.0.0.1 to 10.255.255.254."""
    ips = []
    # Generate required number of IP addresses.
    cidr = '16'
    # 10.0.0.0/16 = 65,534 IP addresses.
    if count > 65534:
        # 10.0.0.0/15 = 131,070 IP addresses.
        cidr = '15'
    elif count > 131070:
        cidr = '14'
    elif count > 262142:
        cidr = '13'
    elif count > 524286:
        # 10.0.0.0/12 = 1,048,574 IP addresses.
        cidr = '12'
    if count > 1048574:
        # 10.0.0.0/11 = 2,097,150 IP addresses.
        cidr = '11'
    elif count > 2097150:
        cidr = '10'
    elif count > 4194302:
        cidr = '9'
    elif count > 8388606:
        # 10.0.0.0/11 = 16,777,214 IP addresses.
        cidr = '8'
    ips = list(ipaddress.ip_network('10.0.0.0/%s' % cidr).hosts())
    # Randomize if requested.
    if random:
        shuffle(ips)
    return ips


def fake_netbios_names(count):
    """Return a list of COUNT fake IP addresses from 10.0.0.1 to 10.255.255.254."""
    print ('Generating fake netBIOS names...')
    netbiosNames = set()
    # Show progress bar.
    widgets = [Percentage(),
               ' ', Bar(),
               ' ', AdaptiveETA()]
    # Count number of plugins imported for progress bar
    pbar = ProgressBar(widgets=widgets, maxval=count).start()
    # Generate required number of netBIOS names.
    for i in range(count):
        netbiosNames.add(''.join(random.choice(string.ascii_uppercase + string.digits)
                                 for _ in range(15)))
        pbar.update(len(netbiosNames))
    pbar.finish()
    return netbiosNames


def build_host(hostXml, ipAddress, netbiosName, hostStart, scanDuration):
    """Return a  .nessus <ReportHost> string node with plugins data"""
    logger.debug("hostXml = %s" % hostXml)
    logger.debug("ipAddress = %s" % ipAddress)
    logger.debug("netbiosName = %s" % netbiosName)
    logger.debug("hostStart = %s" % hostStart)
    logger.debug("scanDuration = %s" % scanDuration)
    # Convert IP address type to string.
    ipAddress = str(ipAddress)
    # Update root tag with IP address.
    hostXml.set('name', ipAddress)
    # Update each child tag by attribute.
    for t in hostXml['HostProperties'].iterchildren():
        if t.attrib['name'] == 'HOST_START':
            # TODO
            # t._setText(hostStart)
            pass
        elif t.attrib['name'] == 'HOST_END':
            # TODO
            # hostEnd = datetime.datetime.strptime(
            #     hostStart, '%c') + datetime.timedelta(seconds=duration)
            # t._setText(hostEnd)
            pass
        elif t.attrib['name'] == 'host-ip':
            t._setText(ipAddress)
        elif t.attrib['name'] == 'netbios-name':
            t._setText(netbiosName)
    # Add plugin data <ReportItem> tags.
    newHostXml = etree.tostring(hostXml)
    return newHostXml

    # UPDATE <ReportHost name="172.26.85.51"><HostProperties>
    # <tag name="LastUnauthenticatedResults">1463386585</tag>
    # <tag name="policy-used">Credentialed Patch Audit</tag>
    # <tag name="patch-summary-total-cves">0</tag>
    # <tag name="system-type">general-purpose</tag>
    # <tag name="operating-system">Microsoft Windows Server 2008 R2 Standard Service Pack 1</tag>
    # <tag name="Credentialed_Scan">false</tag>
    # UPDATE <tag name="netbios-name">TARGET-SHAREPT</tag>
    # UPDATE <tag name="HOST_END">Mon May 16 04:16:25 2016</tag>
    # UPDATE <tag name="host-ip">172.26.85.51</tag>
    # UPDATE <tag name="HOST_START">Mon May 16 04:12:31 2016</tag>
    # </HostProperties>


# Command line parameters
parser = argparse.ArgumentParser()
parser.add_argument('-c', "--count", type=str, required=True,
                    help="Number of hosts to create")
parser.add_argument('-i', "--importNessus", nargs='+', type=str, required=True,
                    help="Filenames of .nessus files to import")
parser.add_argument('-e', "--exportNessus", type=str, required=True,
                    help="Filename prefix to export .nessus file to.")
parser.add_argument('-d', "--dateScansRan", type=str,
                    help="Date scans ran in YYYY-MM-DDTHH:MM:SS format")
# parser.add_argument('-p', "--paginate", type=str,
# help="Paginate Nessus files by a count of this many hosts.")
parser.add_argument('-r', "--random", type=str,
help="Randomize hosts inputted.")
parser.add_argument('-u', "--upload", action='store_true',
                    help="Upload nessus files.")
parser.add_argument('-v', "--verbose", action='store_true',
                    help="Log in verbose mode.")
args = parser.parse_args()

# Check for english numeric abbreviations.
if args.count[-1:].upper() == 'K':
    args.count = int(args.count[:-1]) * 1000
elif args.count[-1:].upper() == 'M':
    args.count = int(args.count[:-1]) * 1000000

# Validate input.
# Check if count is a number.
args.count = int(args.count)
# if args.count > 16777216:
#   print('Unsupported. Host count must be less than 16777217.')
#   exit(1)
if args.count > 16777214:
    print('Unsupported. Host count must be less than 16777215.')
    exit(1)
# # Check if dateScansRan is valid.
# if not re.match('\d\d\d\d-\d\d-\d\d\T\d\d:\d\d:\d\d', args.dateScansRan):
#     print('Date scans must be in YYYY-MM-DDTHH:MM:SS format.')
#     exit(1)
# # Datetime must be in "YYYY-MM-DDTHH:MM:SSmZ" format. Add '0Z'.
# args.dateScansRan += '0Z'

# Reduce noise from requests library.
logging.getLogger('requests').setLevel(logging.CRITICAL)
# Log directory creation.
logPath = os.path.expanduser('~') + '/logs/' + os.path.basename(sys.argv[0])
os.makedirs(logPath, exist_ok=True)
# load config from dictConfig
loggingConfig = {
    'version': 1,
    'disable_existing_loggers': False,  # this fixes the problem

    'formatters': {
        'standard': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        },
    },
    'handlers': {
        'default': {
            'level': 'INFO',
            "class": "logging.handlers.RotatingFileHandler",
            #"formatter": "simple",
            "filename": "%s/info.log" % logPath,
            "maxBytes": 10485760,
            "backupCount": 20,
            "encoding": "utf8"
        },
    },
    'loggers': {
        '': {
            'handlers': ['default', ],
            'level': 'DEBUG',
            'propagate': True
        }
    }
}
if args.verbose:
    # Log in verbose mode.
    loggingConfig['handlers']["debug_file_handler"] = {
        "class": "logging.handlers.RotatingFileHandler",
        "level": "DEBUG",
        #"formatter": "simple",
        "filename": "%s/debug.log" % logPath,
        "maxBytes": 10485760,
        "backupCount": 20,
        "encoding": "utf8"
    }
    loggingConfig['loggers']['']['handlers'].append('debug_file_handler')
# Load logging config.
logging.config.dictConfig(loggingConfig)
logger = logging.getLogger(__name__)
logger.debug('Start')


if args.upload:
    config = configparser.ConfigParser()
    config.read('nessus_cloud.cfg')
    username = config.get("Nessus Cloud", "username")
    password = config.get("Nessus Cloud", "password")
    if not (username and password):
        exit(1)
    # Capture cookies.
    session = requests.Session()
    # Set up request.
    baseurl = "https://dswx-preview.svc.nessus.org"
    url = baseurl + "/session"
    data = {'username':username, 'password':password}
    # Make request.
    response = session.post(url, data=data)
    contentJson = json.loads(response.text)
    # Extract token.
    try:
        token = 'token=%s' % contentJson['token']
    except KeyError:
        # Wrong credentials.
        logger.error('Wrong credentials.')
        exit(1)
    response.raise_for_status()
    session.headers.update({'X-Cookie': token})

# Import nessus file(s).
data = []
xmlHeaders = []
xmlFooters = []
for f in args.importNessus:
    # Import each file.
    with open(f, 'rb', 0) as file, \
        mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as scanFile:
        # Check if there are any hosts scanned.
        scanResultsStart = scanFile.find(b'<ReportHost ')
        if scanResultsStart == -1:
            # No hosts, skip
            continue
        # Hosts exists. 
        # Store beginning of file.
        xmlHeader = scanFile[:scanResultsStart]
        scanResultsEnd = scanFile.find(b'</Report>')
        xmlFooter = scanFile[scanResultsEnd:]
        # Add to list of files.
        xmlHeaders.append(xmlHeader)
        logger.debug (len(xmlHeaders))
        xmlFooters.append(xmlFooter)
    # Store data.
    data.extend(import_nessus_file(f))
# Data imported.
logger.debug('data = %s' % str(data))
logger.debug('len(data) = %s' % str(len(data)))
# All vulns in data from all file(s). This will change.
# # Set up fake mac addresses.
# macAddresses = fake_mac_addresses(args.count, args.random)
# Set up fake IP addresses and hostnames. They are the same.
ipAddresses = fake_ip_addresses(args.count, args.random)
# hostnames = ipAddresses
# # Set up fake netBIOS names.
netBiosNames = fake_netbios_names(args.count)
# Set up fake DNS names.
# dnsNames = fake_dns_names(args.count, args.random)
# Write to string.
exportNessus = b''
exportCount = 0
# Keep track of filenames in case of uploading.
filenames = []
print ('Generating fake nessus file(s)...')
# Show progress bar.
widgets = [Percentage(),
           ' ', Bar(),
           ' ', AdaptiveETA()]
# Count number of plugins imported for progress bar
pbar = ProgressBar(widgets=widgets, maxval=args.count).start()
for i in range(args.count):
    # Check every 100 hosts the size of the file for pagination
    if i % 100 == 0 and i != 0:
        # Paginate
        logger.debug('Paginate')
        logger.debug(exportNessus)
        with open(args.exportNessus + str(exportCount) + str('.nessus'), "wb") as w:
            w.write(xmlHeaders[0])
            w.write(exportNessus)
            w.write(xmlFooters[0])
        # Increase filename.
        exportCount += 1
        # Reset Nessus data file.
        exportNessus = b''
    # Create new host.
    host = data[random.randint(0,len(data)-1)]
    newHost = build_host(host['hostXml'], 
        ipAddresses.pop(), 
        # dnsNames.pop(), 
        netBiosNames.pop(), 
        args.dateScansRan, 
        host['scanDuration'])
    exportNessus += newHost
    pbar.update(i)
    # Write final file.
    filename = args.exportNessus + str(exportCount) + str('.nessus')
    with open(filename, "wb") as w:
                w.write(xmlHeaders[0])
                w.write(exportNessus)
                w.write(xmlFooters[0])
    filenames.append(filename)
# Files written.
pbar.finish()
# Upload if requested.
if args.upload:
    print ('Uploading and importing .nessus files...')
    pbar = ProgressBar(widgets=widgets, maxval=len(filenames)).start()
    i = 0
    for f in filenames:
        # Upload file
        url = baseurl + '/file/upload'
        files = {'Filedata': open(f, 'rb')}
        # Make request.
        response = session.post(url, files=files)
        logger.debug('response.headers = %s' % str(response.headers))
        logger.debug('response.text = %s' % response.text)
        contentJson = json.loads(response.text)
        # Import uploaded file.
        uploadedFilename = contentJson['fileuploaded']
        url = baseurl + '/scans/import?include_aggregate=1'
        data = {'file': uploadedFilename}
        # Make request.
        response = session.post(url, data=data)
        response.raise_for_status()
        i += 1
        pbar.update(i)
print ('Done.')
pbar.finish()