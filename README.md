# Simple Nmap Logger
A simple parsing and logging tool that records the human readable output of an nmap scan on target(s) specified in a target file along with recording any changes since a previous nmap scan using the tool. Recorded changes range from:
* host status (whether it is up/running or down/shutdown/cannont be reached)
* port state (whether a port is open or closed and how this was checked)
* port service (details the service version, name of service, OS if applicable, use of SSL/TLS if applicable, etc)

All data is kept in a rolling log file so users can refer back to the previous state of target(s) as desired
# Disclaimer
Users of the tool should only use nmap on target(s) that they have explicit permission to scan
