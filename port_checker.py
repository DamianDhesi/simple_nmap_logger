from io import TextIOWrapper
import subprocess
import xml.etree.ElementTree as ET
import os
import sys
import datetime

result_file = "nmap_results.xml"
prev_file = "nmap_results_prev.xml"
log_file = "port_check.log"
temp_file = ".temp.log"

# Grabs data from an nmap xml tree and verify if changes occured in given values
def checkForPortChanges(log_file: TextIOWrapper, port: str, cur_port_category: ET.Element, 
                   prev_port_category: ET.Element, data_name: str, print_name: str):
    cur_value = cur_port_category.get(data_name)
    prev_value = prev_port_category.get(data_name)
    if (cur_value != prev_value):
        log_file.write("\tPort {0} {1} changed from {2} to {3}\n"
                .format(port, print_name, prev_value, cur_value))
        return True
    return False

# rename previous result file if it exists
if (os.path.isfile(result_file)):
    os.rename(result_file, prev_file)

# run nmap with full options
nmap_command = ["nmap", "-iL", "targets.txt", "-n", "-p1-65535", 
                "-sV", "-oX", result_file, "-oN", temp_file]
subprocess.run(nmap_command, capture_output=True)

# add human readable output to log file
log = open(log_file, "a")
temp = open(temp_file, "r")

cur_data = ET.parse(result_file).getroot()
cur_utc_date = datetime.datetime.fromtimestamp(int(cur_data.attrib["start"]), datetime.timezone.utc)
log.write("Scan Started (UTC): {0}\n".format(cur_utc_date.isoformat()))

log.write(temp.read())

temp.close()
os.remove(temp_file)

# skip checking for changes if no previous data
if (not os.path.exists(prev_file)):
    log.write("CHANGES:\n\tNO PREVIOUS DATA\n\n")
    sys.exit(os.EX_OK)

# parse nmap output to check for changes
prev_data = ET.parse(prev_file).getroot()
log.write("CHANGES:\n")

cur_hosts = list(cur_data.iter("host"))
prev_hosts = list(prev_data.iter("host"))

cur_hostnames = list(map(lambda host: host.find("hostnames").find("hostname").get("name"), cur_hosts))
prev_hostnames = list(map(lambda host: host.find("hostnames").find("hostname").get("name"), prev_hosts))

# report if any hosts have been added or removed
for prev_hostname in prev_hostnames:
    if (prev_hostname not in cur_hostnames):
        log.write("{0} is no longer being checked\n".format(prev_hostname))

for cur_hostname in cur_hostnames:
    if (cur_hostname not in prev_hostnames):
        log.write("Host {0} is now being scanned and recorded\n".format(cur_hostname))

# check details of each host
for i, prev_hostname in enumerate(prev_hostnames):
    if (prev_hostname in cur_hostnames):
        log.write(prev_hostname + "\n")
        cur_host = cur_hosts[cur_hostnames.index(prev_hostname)]
        prev_host = prev_hosts[i]

        changes = False

        # check if hosts have gone up or down
        cur_host_state = cur_host.find("status").get("state")
        prev_host_state = prev_host.find("status").get("state")
        if (cur_host_state != prev_host_state):
            log.write("\tHost {0} state changed from {1} to {2}\n\n"
                  .format(prev_hostname, prev_host_state,
                          cur_host_state))
            continue
        
        # check if ports added or removed
        cur_ports = list(cur_host.iter("port"))
        prev_ports = list(prev_host.iter("port"))

        cur_portids = list(map(lambda port: port.get("portid"), cur_ports))
        prev_portids = list(map(lambda port: port.get("portid"), prev_ports))

        for portid in prev_portids:
            if (portid not in cur_portids):
                changes = True
                log.write("\tPort {0} has been closed\n".format(portid))
        
        for portid in cur_portids:
            if (portid not in prev_portids):
                changes = True
                log.write("\tPort {0} has been added\n".format(portid))

        for j, prev_portid in enumerate(prev_portids):
            if (prev_portid in cur_portids):
                cur_port = cur_ports[cur_portids.index(prev_portid)]
                prev_port = prev_ports[j]

            # check if port state changed
            cur_port_state = cur_port.find("state")
            prev_port_state = prev_port.find("state")
            port_state_datatypes = [("state", "state"), 
                                    ("reason", "reason for service state")]

            for datatype in port_state_datatypes:
                if (checkForPortChanges(log, prev_portid, cur_port_state, 
                                         prev_port_state, datatype[0], 
                                         datatype[1])):
                    changes = True

            # check if port service changed
            cur_port_service = cur_port.find("service")
            prev_port_service = prev_port.find("service")
            port_service_datatypes = [("name", "service name"), 
                                      ("product", "service product"),
                                      ("version", "service version"),
                                      ("extrainfo", "service extrainfo"),
                                      ("tunnel", "service tunnel"),
                                      ("ostype", "service OS")]
            
            for datatype in port_service_datatypes:
                if (checkForPortChanges(log, prev_portid, cur_port_service, 
                                        prev_port_service, datatype[0],
                                        datatype[1])):
                    changes = True

        if (not changes):
            log.write("\tno changes\n")
        log.write("\n")

log.close()

# previous xml no longer needed
os.remove(prev_file)

MAX_DAYS_OLD = 14

# delete entries older than a given age, rolling log
with open(log_file, "r") as log:
    with open (temp_file, "w") as new_log:
        keep_line = True
        for line in log:

            if ("Scan Started (UTC):" in line):
                oldest_utc_time = datetime.datetime.fromisoformat(line.split()[3])
                dif_time = cur_utc_date - oldest_utc_time
                keep_line = dif_time.days < MAX_DAYS_OLD

            if (keep_line):
                new_log.write(line)

os.remove(log_file)
os.replace(temp_file, log_file)