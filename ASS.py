import shodan
import requests
import argparse
import ipaddress
import sys
import time
import csv
import json
from os import system, name
from colorama import init, Fore, Style
from prettytable import PrettyTable


# define Python user-defined exceptions
class Error(Exception):
    """Base class for other exceptions"""
    pass


class BadIpPatternException(Error):
    """Bad IP pattern exception"""
    pass


class MyParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write('error: %s\n' % message)
        self.print_help()
        sys.exit(2)


def clear():
    # for windows
    if name == 'nt':
        _ = system('cls')
    else:
        _ = system('clear')


def banner():
    print(Fore.LIGHTWHITE_EX+"""
⣿⣿⡻⠿⣳⠸⢿⡇⢇⣿⡧⢹⠿⣿⣿⣿⣿⣾⣿⡇⣿⣿⣿⣿⡿⡐⣯⠁ ⠄⠄
⠟⣛⣽⡳⠼⠄⠈⣷⡾⣥⣱⠃⠣⣿⣿⣿⣯⣭⠽⡇⣿⣿⣿⣿⣟⢢⠏⠄ ⠄
⢠⡿⠶⣮⣝⣿⠄⠄⠈⡥⢭⣥⠅⢌⣽⣿⣻⢶⣭⡿⠿⠜⢿⣿⣿⡿⠁⠄⠄
⠄⣼⣧⠤⢌⣭⡇⠄⠄⠄⠭⠭⠭⠯⠴⣚⣉⣛⡢⠭⠵⢶⣾⣦⡍⠁⠄⠄⠄⠄
⠄⣿⣷⣯⣭⡷⠄⠄⢀⣀⠩⠍⢉⣛⣛⠫⢏⣈⣭⣥⣶⣶⣦⣭⣛⠄⠄⠄⠄⠄
⢀⣿⣿⣿⡿⠃⢀⣴⣿⣿⣿⣎⢩⠌⣡⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⠄⠄⠄
⢸⡿⢟⣽⠎⣰⣿⣿⣿⣿⣿⣿⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠄⠄
⣰⠯⣾⢅⣼⣿⣿⣿⣿⣿⣿⡇⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠄""",end='')
    print(Fore.LIGHTYELLOW_EX+"""
 +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+ +-+-+-+-+-+-+
 |A|u|t|o|m|a|t|i|c| |S|h|o|d|a|n| |S|e|a|r|c|h|
 +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+ +-+-+-+-+-+-+"""+ Style.RESET_ALL,end='')
    print(Fore.LIGHTWHITE_EX+"""
⢸⣟⣧⡻⣿⣿⣿⣿⣿⣿⣿⣧⡻⣿⣿""",end='')
    print(Fore.LIGHTRED_EX+"""    by @F3715H"""+ Style.RESET_ALL,end='')
    print(Fore.LIGHTWHITE_EX+"""⣿⣿⣿⣿⣿⣿⠄
⠈⢹⡧⣿⣸⠿⢿⣿⣿⣿⣿⡿⠗⣈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠄
⠄⠘⢷⡳⣾⣷⣶⣶⣶⣶⣶⣾⣿⣿⢀⣶⣶⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⠄
⠄⠄⠈⣵⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠄⠄
⠄⠄⠄⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⠄⠄⠀⠀⠀⠀  
""" + Style.RESET_ALL)


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--api", help="Returns information about the API plan belonging to the given API key.", action='store_true')
    parser.add_argument("-i", "--ip", help="Returns all services that have been found on the given host IP(s). Separate Ip addresses by space", action='append', nargs='*')
    parser.add_argument("-n", "--network", help="Returns all services that have been found on the given network cluser.", action='append', nargs='*')
    parser.add_argument("-o", "--output", help="Exports and save results to csv file in provided location.")
    parser.add_argument("-v", "--verbose", help="List all IP addresses (also these not found in shodan) ", action='store_true')
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    return args


def create_table():
    table_headers = PrettyTable(['IP Address', 'Hostnames', 'Operating System', 'Open Ports', 'Organization', 'Last Update','State'])
    table_headers.align = "l"
    return table_headers


def scan(parser, api_key):
    count = 0
    list_of_findings = []

    # run scan for provided network
    if parser.network:
        for networks in parser.network[0]:
            try:
                assert '/' in networks
            except AssertionError:
                raise BadIpPatternException("Expected network cluster got single IP instead")
            else:
                net4 = ipaddress.ip_network(networks)
                for x in net4.hosts():
                    count += 1
                    list_of_findings = query_shodan(str(x), list_of_findings, api_key)
                    update_results(parser.network, list_of_findings, table_headers, count, x, net4)

    # run scan for specific ip
    elif parser.ip:
        try:
            assert '/' not in parser.ip
        except AssertionError:
            raise BadIpPatternException("IP address(es) expeceted got network cluster instead")
        else:
            for ips in parser.ip:
                for ip in ips:
                    count += 1
                    list_of_findings = query_shodan(ip, list_of_findings, api_key)
                    update_results(ips, list_of_findings, table_headers, count, ip, None)

    elif parser.api:
        print("API Key: {}".format(api_key))
        api = shodan.Shodan(api_key)
        for item in api.info():
            print("{}: {}".format(item, api.info()[item]))



    # save the file if requested
    if parser.output:
        output_csv(list_of_findings)


def query_shodan(target, list_of_findings, api_key):
    api = shodan.Shodan(api_key)
    list_test = list_of_findings
    time.sleep(1)
    dns_resolve = 'https://api.shodan.io/dns/resolve?hostnames=' + target + '&key=' + api_key
    try:
        # First we need to resolve our targets domain to an IP
        resolved = requests.get(dns_resolve)
        host_ip = resolved.json()[target]

        # Then we need to do a Shodan search on that IP
        host = api.host(host_ip)
        service = []
        hostname = str(host.get('hostnames', 'N/A')).translate({ord(c): None for c in "[]'"})
        if len(hostname) == 0:
            hostname = Fore.LIGHTBLACK_EX+'N/A'+ Style.RESET_ALL

        # Print all banners
        for item in host['data']:
            service.append(item['port'])

        dict1 = {
            "IP Address": host['ip_str'],
            "Hostnames": hostname,
            "Operating System": str(host.get('os', Fore.LIGHTBLACK_EX+'N/A'+ Style.RESET_ALL)).replace('None', Fore.LIGHTBLACK_EX+'N/A'+ Style.RESET_ALL),
            "Open Ports": str(service).translate({ord(c): None for c in "[]"}),
            "Organization": host.get('org',Fore.LIGHTBLACK_EX+'N/A'+ Style.RESET_ALL),
            "Last Update": host.get('last_update', Fore.LIGHTBLACK_EX+'N/A'+ Style.RESET_ALL),
            "State": Fore.LIGHTGREEN_EX+"FOUND" + Style.RESET_ALL }

        list_test.append(dict1.copy())
        return list_test

    except:
        dict1 = {
            "IP Address": target,
            "Hostnames": Fore.LIGHTBLACK_EX+'N/A',
            "Operating System": Fore.LIGHTBLACK_EX+'N/A',
            "Open Ports": Fore.LIGHTBLACK_EX+'N/A',
            "Organization": Fore.LIGHTBLACK_EX+'N/A',
            "Last Update": Fore.LIGHTBLACK_EX+'N/A',
            "State": Fore.LIGHTRED_EX + 'NOT FOUND' }

        list_test.append(dict1.copy())
        return list_of_findings


def update_results(network, list_of_findings, table_headers, count, x, net4):
    clear()
    banner()
    hosts_amount = len(network)
    not_found = 0

    if net4:
        hosts_amount = 0
        for item in network[0]:
            item = ipaddress.ip_network(item)
            hosts_amount += len(list(item))-2
        network = str(network[0])

    for dictionary in list_of_findings:
        if dictionary['State'] == (Fore.LIGHTRED_EX + 'NOT FOUND'):
            not_found += 1

    print("Scan results for: {}\nProgress: {}/{} - {}%\nChecking IP {}\nHosts found: {}\nHosts not found: {}"
          .format(str(network).translate({ord(c): None for c in "[]'"}),
                  count,
                  hosts_amount,
                  round((count/(hosts_amount))*100, 2),
                  x,
                  len(list_of_findings) - not_found,
                  not_found,
                  0
                  )
          )
    print("------------------------------------------------------------------------------")
    if parser.verbose:
        for dictionary in list_of_findings:
            table_headers.add_row([
                Fore.LIGHTBLUE_EX+str(dictionary['IP Address']) + Style.RESET_ALL,
                Fore.YELLOW+str(dictionary['Hostnames']) + Style.RESET_ALL,
                Fore.YELLOW+str(dictionary['Operating System']) + Style.RESET_ALL,
                Fore.YELLOW+str(dictionary['Open Ports']) + Style.RESET_ALL,
                Fore.YELLOW+str(dictionary['Organization']) + Style.RESET_ALL,
                Fore.YELLOW+str(dictionary['Last Update'][:10]) + Style.RESET_ALL,
                Fore.YELLOW+str(dictionary['State']) + Style.RESET_ALL
            ])
    else:
        for dictionary in list_of_findings:
            if dictionary['State'] == (Fore.LIGHTGREEN_EX+"FOUND" + Style.RESET_ALL):
                table_headers.add_row([
                    Fore.LIGHTBLUE_EX + str(dictionary['IP Address']) + Style.RESET_ALL,
                    Fore.YELLOW + str(dictionary['Hostnames']) + Style.RESET_ALL,
                    Fore.YELLOW + str(dictionary['Operating System']) + Style.RESET_ALL,
                    Fore.YELLOW + str(dictionary['Open Ports']) + Style.RESET_ALL,
                    Fore.YELLOW + str(dictionary['Organization']) + Style.RESET_ALL,
                    Fore.YELLOW + str(dictionary['Last Update'][:10]) + Style.RESET_ALL,
                    Fore.YELLOW + str(dictionary['State']) + Style.RESET_ALL
                ])

    print(table_headers)
    table_headers.clear_rows()


def output_csv(data):
    # open the file in the write mode
    with open(parser.output, 'w', encoding='UTF8', newline='') as f:
        # create the csv writer
        writer = csv.DictWriter(f, fieldnames=[
            'IP Address', 'Hostnames', 'Operating System', 'Open Ports', 'Organization', 'Last Update', 'State'
        ])
        writer.writeheader()

        for result in data:
            for item in result:
                if "N/A" in result[item]:
                    result[item] = "N/A"
                elif item == 'State':
                    if "NOT FOUND" in result[item]:
                        result[item] = 'NOT FOUND'
                    elif "FOUND" in result[item]:
                        result[item] = 'FOUND'
        # write a row to the csv file
        writer.writerows(data)


if __name__ == '__main__':
    init()
    api_key = "INSERT_YOUR_API_KEY_HERE" # CHANGE IT
    parser = create_parser()
    table_headers = create_table()
    scan(parser, api_key)
