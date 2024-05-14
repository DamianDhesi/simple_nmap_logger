# nmap_parser
A simple parser that records the human readable output of an nmap scan on a target file along with recording any changes since a previous nmap scan. Recorded changes range from:
* host status (whether it is up or down)
* port state (whether a port is open or closed)
* port service (details the service version, name of service, OS if applicable, etc)

All data is kept in a rolling log file so users can refer back to the previous state of target(s) as desired
# disclaimer
Users of the parser should only use nmap on target(s) that they have explicit permission to scan
