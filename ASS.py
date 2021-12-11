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
    print(Fore.LIGHTWHITE_EX+"""⠀⠀⠀  
    _         /\_/\\
   ( \       /   ``\\
    ) )   __|   n n |
   / /  /`   `'.==Y=)=  
  ( (  /        `"`}
   \ \|    \ """+Fore.LIGHTRED_EX+""" by @P@r7yb0y"""+ Style.RESET_ALL+""" 
    \ \     ),   //
     '._,  /'-\ ( (
    aac  \,,)) \,),)
""" + Style.RESET_ALL)

# Print iterations progress
def printProgressBar (iteration, total, prefix = '', suffix = '', decimals = 1, length = 100, fill = '█', printEnd = "\r"):
    # source code: https://stackoverflow.com/questions/3173320/text-progress-bar-in-the-console
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end = printEnd)
    # Print New Line on Complete
    if iteration == total: 
        print()



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
    table_headers = PrettyTable(['IP Address', 'Hostnames', 'Service Banners', 'Open Ports', 'Organization', 'Last Update','State','Screenshots'])
    table_headers.align = "l"
    return table_headers


def scan(parser, api_key, api_key_screen):
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
                    list_of_findings = query_shodan(str(x), list_of_findings, api_key, api_key_screen)
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
                    list_of_findings = query_shodan(ip, list_of_findings, api_key, api_key_screen)
                    update_results(ips, list_of_findings, table_headers, count, ip, None)

    elif parser.api:
        print("API Key: {}".format(api_key))
        api = shodan.Shodan(api_key)
        for item in api.info():
            print("{}: {}".format(item, api.info()[item]))



    # save the file if requested
    if parser.output:
        output_csv(list_of_findings)

def detect_http(host_ip, item, api_key_screen):
    if "HTTP" in item['data']:
        #print("HTTP SERV DETECTED")
        make_screenshot(host_ip, item['port'], api_key_screen)
        return 1

def detect_banner(item):
    if ("product" in item) or ("version" in item):
        if ("product" in item) and ("version" in item):
            service_banner = f"{item['product']} {item['version']}"
        elif "product" in item:
            service_banner = f"{item['product']}"
        elif "version" in item:
            service_banner = f"{item['version']}"
    else:
        service_banner = f"N/A"
    return service_banner

def query_shodan(target, list_of_findings, api_key, api_key_screen):
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
        service_banners = []
        hostname = str(host.get('hostnames', 'N/A')).translate({ord(c): None for c in "[]'"})
        if len(hostname) == 0:
            hostname = Fore.LIGHTBLACK_EX+'N/A'+ Style.RESET_ALL

        # Print all banners
        counter = 0
        for item in host['data']:
            service.append(f"{item['port']}/{item['transport']}")
            if detect_banner(item) != "N/A":
                service_banners.append(f"{item['port']}:{detect_banner(item)}")
            http = detect_http(host_ip, item, api_key_screen)
            if http:
               counter += 1  
        if len(service_banners) == 0:
            service_banners = (Fore.LIGHTBLACK_EX+'N/A'+ Style.RESET_ALL) 
        else:
            service_banners = str(service_banners).translate({ord(c): None for c in "[']"})
        if counter > 0:
            counter = Fore.LIGHTGREEN_EX + f"{counter}" + Style.RESET_ALL
        dict1 = {
            "IP Address": host['ip_str'],
            "Hostnames": hostname,
            "Service Banners": str(service_banners),
            "Open Ports": str(service).translate({ord(c): None for c in "[']"}),
            "Organization": host.get('org',Fore.LIGHTBLACK_EX+'N/A'+ Style.RESET_ALL),
            "Last Update": host.get('last_update', Fore.LIGHTBLACK_EX+'N/A'+ Style.RESET_ALL),
            "State": Fore.LIGHTGREEN_EX+"FOUND" + Style.RESET_ALL,
            "Screenshots": f"{counter}" }

        list_test.append(dict1.copy())
        return list_test

    except:
        dict1 = {
            "IP Address": target,
            "Hostnames": Fore.LIGHTBLACK_EX+'N/A',
            "Service Banners": Fore.LIGHTBLACK_EX+'N/A',
            "Open Ports": Fore.LIGHTBLACK_EX+'N/A',
            "Organization": Fore.LIGHTBLACK_EX+'N/A',
            "Last Update": Fore.LIGHTBLACK_EX+'N/A',
            "State": Fore.LIGHTRED_EX + 'NOT FOUND',
            "Screenshots": Fore.LIGHTBLACK_EX + "0" + Style.RESET_ALL }

        list_test.append(dict1.copy())
        return list_of_findings

def make_screenshot(host_ip, port,api_key_screen):
    if "443" in str(port):
        screenshot_url = f"https://api.apiflash.com/v1/urltoimage?access_key={api_key_screen}&url=https://{host_ip}:{port}"
    else:
        screenshot_url = f"https://api.apiflash.com/v1/urltoimage?access_key={api_key_screen}&url=http://{host_ip}:{port}"
    response = requests.get(screenshot_url)
    file_name = f"{host_ip}_p{port}.png"
    file = open(file_name, "wb")
    file.write(response.content)
    file.close()

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
    
    print("Scan results for: {}\nChecking IP {}\nHosts found: {}\nHosts not found: {}"
          .format(str(network).translate({ord(c): None for c in "[]'"}),
                  x,
                  len(list_of_findings) - not_found,
                  not_found,
                  0
                  )
          )
    


    printProgressBar(int(count), int(hosts_amount), prefix = 'Progress:', suffix = 'Complete', length = 50)
    print("\n")
    if parser.verbose:
        for dictionary in list_of_findings:
            table_headers.add_row([
                Fore.LIGHTBLUE_EX + str(dictionary['IP Address']) + Style.RESET_ALL,
                Fore.YELLOW + str(dictionary['Hostnames']) + Style.RESET_ALL,
                Fore.YELLOW + str(dictionary['Service Banners']) + Style.RESET_ALL,
                Fore.YELLOW + str(dictionary['Open Ports']) + Style.RESET_ALL,
                Fore.YELLOW + str(dictionary['Organization']) + Style.RESET_ALL,
                Fore.YELLOW + str(dictionary['Last Update'][:10]) + Style.RESET_ALL,
                Fore.YELLOW + str(dictionary['State']) + Style.RESET_ALL,
                Fore.LIGHTBLACK_EX + str(dictionary['Screenshots']) + Style.RESET_ALL
            ])
    else:
        for dictionary in list_of_findings:
            if dictionary['State'] == (Fore.LIGHTGREEN_EX+"FOUND" + Style.RESET_ALL):
                table_headers.add_row([
                    Fore.LIGHTBLUE_EX + str(dictionary['IP Address']) + Style.RESET_ALL,
                    Fore.YELLOW + str(dictionary['Hostnames']) + Style.RESET_ALL,
                    Fore.YELLOW + str(dictionary['Service Banners']) + Style.RESET_ALL,
                    Fore.YELLOW + str(dictionary['Open Ports']) + Style.RESET_ALL,
                    Fore.YELLOW + str(dictionary['Organization']) + Style.RESET_ALL,
                    Fore.YELLOW + str(dictionary['Last Update'][:10]) + Style.RESET_ALL,
                    Fore.YELLOW + str(dictionary['State']) + Style.RESET_ALL,
                    Fore.LIGHTBLACK_EX + str(dictionary['Screenshots']) + Style.RESET_ALL
                ])

    print(table_headers)
    table_headers.clear_rows()


def output_csv(data):
    # open the file in the write mode
    with open(parser.output, 'w', encoding='UTF8', newline='') as f:
        # create the csv writer
        writer = csv.DictWriter(f, fieldnames=[
            'IP Address', 'Hostnames', 'Service Banners', 'Open Ports', 'Organization', 'Last Update', 'State', 'Screenshots'
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
    api_key = "" # PLACE YOUR SHODAN API KEY HERE
    api_key_screen = "" # PLACE YOUR https://api.apiflash.com API KEY HERE
    parser = create_parser()
    table_headers = create_table()
    scan(parser, api_key, api_key_screen)
