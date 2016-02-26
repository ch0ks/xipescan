#!/usr/bin/python
__author__ = 'Adrian Puente Z. <apuente@medallia.com>'
__company__ = 'Medallia Inc.'
__version__ = '0.0'
__last_modification__ = '2016.02.16'

import sys
import nmap
import argparse
import iptools


def printMessage(strMsg): print ("[*] %s" % strMsg)


def printSuccess(strMsg): print ("[+] %s" % strMsg)


def printError(strMsg): print ("[!] %s" % strMsg)


def remove_duplicates_in_list(seq):
    seen = set()
    seen_add = seen.add
    return [x for x in seq if not (x in seen or seen_add(x))]


def filetolist(filename):
    """
    This function reads the file and reads every line to a tuple.

    :param filename: the name of the file to read. It can be an absolute path file or just a file located where this script is.
    :type filename: str
    :return: a tuple containing the content of the file line by line.
    """
    lines = list()
    with open(filename) as f:
        filelines = f.readlines()
    f.close()
    for line in filelines: lines.append(line.rstrip())
    return remove_duplicates_in_list(lines)


def callback_result(host, scan_result):
    """
    this function is used internally by nmap to report the findings.

    :param host: host scanned.
    :type host: str
    :param scan_result:  scanned host results
    :type scan_result: str
    :return: Nothing
    """
    active_ips = list()
    if not scan_result['scan']:
        printError("Error while scanning %s" % host)
        return False
    state = scan_result['scan'][host]['status']['state']
    print "State " + state
    if state is "up": active_ips.insert(host)
    printSuccess("Host scanned %s, status %s." % (host, state))
    print active_ips
    return False


def discovery(file_name, output_file):
    """
    This function performs discovery scan using predefined parameters, once finished it returns a tuple with the active hosts.

    :param file_name: filename containing the host to scan one host by line.
    :type file_name: str
    :param output_file: file where to write the active hosts found.
    :type output_file: str
    :return: a tuple with the active hosts.
    """
    nm = nmap.PortScanner()
    tcp_ports = "21-23,25,53,80,88,110-111,135,139,443,445,515,1433,1521,2222,8080,8443"
    udp_ports = "53,111,135,137,161,500"
    nm_arguments = "-sP -Pn -PU" + udp_ports + " -PS" + tcp_ports

    active_ips = list()
    iplist = list()
    host_list = filetolist(file_name)
    for host in host_list:
        if "/" in host:
            iplist += iptools.IpRange(host)
        else:
            iplist.append(host)
    iplist = remove_duplicates_in_list(iplist)
    iplist.sort()

    printMessage("Scanning a total of %i hosts." % len(iplist))
    for host in iplist:
        printMessage("Scanning %s" % host)
        nm.scan(hosts=host, arguments=nm_arguments)
        active_ips += nm.all_hosts()

    if len(active_ips) is 0:
        printError("No active hosts found.")
        sys.exit(1)

    printSuccess("Scan completed.")
    active_ips = remove_duplicates_in_list(active_ips)
    printSuccess("Found %i active hosts." % len(active_ips))
    f = open(output_file, "w")
    f.write("\n".join(active_ips))
    f.close()
    printSuccess("File %s created." % output_file)
    return active_ips


def main():
    """
    The main program.

    :return: errorlevel 1 if there has been an error and 0 if the operation was successful.
    """
    strDesc = '''Xipe - Network Discovery Scanner.'''
    parser = argparse.ArgumentParser(description=strDesc)

    parser.add_argument("-d", "--discoverfromfile",
                        nargs=2,
                        default=False,
                        metavar=("<IP List>", "<Output File Name>"),
                        help="performs a discovery scan on the hosts in the file and creates an output file containing active hosts.")
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()

    if args.discoverfromfile:
        discovery(*args.discoverfromfile)

    sys.exit(0)


if __name__ == "__main__":
    main()
