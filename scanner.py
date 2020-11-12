import socket
from ipaddress import *
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
import scapy.all as scapy
from scapy.layers.l2 import ARP
from scapy.sendrecv import sr
import argparse


class PortScanner:

    def __init__(self, args):
        if args.portslst:
            self.ports_range = list(map(int, args.portslst))
        if args.ipslst:
            self.ipslst = args.ipslst
        elif args.network_id:
            network_id = args.network_id
            self.ipslst = list(ip_network(network_id).hosts())
        else:
            network_id = scapy.get_if_addr(scapy.conf.iface)[:-2]+'0/24'
            self.ipslst = list(ip_network(network_id).hosts())
        self.ipsq = Queue()
        self.result = {}

    # implementing with scapy arp ping method
    def ips_scanner(self, ip):
        ip = str(ip)
        a = sr(ARP(pdst=[ip]), timeout=1, verbose=0)
        if len(a[0].res) > 0:
            self.ipsq.put(ip)

    # scanning for open ports per ip by streaming with sockets
    @staticmethod
    def port_scanner(ip, port, q: Queue):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect_ex((ip, port))
            # if a connection established putting port number inside q (to avoid deadlock)
            if result == 0:
                q.put(port)
            s.close()
        except socket.error as exc:
            print(f"Caught exception socket.error : {exc}")

    # executing open port search
    def ip_handler(self):
        while True:
            # waiting for new ip
            ip = self.ipsq.get()
            if ip:
                # adding another entry to the dictionary: key - ip value - ports list
                self.result[ip] = []
                qu = Queue()
                # executing thread poll in order to find open ports

                with ThreadPoolExecutor(5000) as executor:
                    for i in range(self.ports_range[0], self.ports_range[1]):
                        executor.submit(self.port_scanner, ip, i, qu)
                # dumping all the ports to the final dictionary
                while qu.qsize() > 0:
                    self.result[ip].append(qu.get())
            else:
                break

    def run(self):
        # executing thread pool - for pinging the ips and check if they are alive
        with ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(self.ips_scanner, self.ipslst)
        # after finished adding FALSE boolean argument to determine ip handler there's no more ips
        self.ipsq.put(False)
        self.ip_handler()
        # returning completed with ips and open ports in the network
        return self.result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-l', '--ips_list', dest='ipslst', default=None, nargs='*',
                        help='insert above the ips list you would like to check otherwise it will be set to default.')
    parser.add_argument('-p', '--ports_range', dest='portslst', default=[1, 65535], nargs='*',
                        help='insert above the ports range you would like to check otherwise it will be set to default.')
    parser.add_argument('-n', '--network_id', dest='network_id', default=None,
                        help='if your subnet mask is not 255.255.255.0 you should insert your network id.')
    try:
        args = parser.parse_args()
    except argparse.ArgumentError as e:
        print(e)
    final_list = PortScanner(args).run()
    found = False
    for ip in final_list:
        if final_list[ip]:
            for port in final_list[ip]:
                found = True
                print(f'{ip}:{port}         LISTENING')

    if not found:
        print(f'couldnt find any open ports in the ips given!')