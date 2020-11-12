import logging
import os
from argparse import Namespace
from time import sleep
import scapy.all as scapy
from scapy.layers.inet import TCP, IP
import datetime
import scanner


class PortDetector:

    def __init__(self):
        # setting logger
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)

        handler = logging.FileHandler(os.path.dirname(os.path.realpath(__file__)) + r'\logs\{:%Y-%m-%d-%H-%M}.log'.format(datetime.datetime.now()),
                                      'w', 'utf-8')  # or whatever
        root_logger.addHandler(handler)
        self.ip = scapy.get_if_addr(scapy.conf.iface)
        self.pck_counter = 0
        self.timeout = 60
        self.period = 60

    # sniffing the network with given timeout
    # passing all packages to pck_handler
    def sniffer(self, open_ports):
        filter = 'tcp and ( '
        for i in open_ports[:-1]:
            filter = "%sport %s or " % (filter, i)
        filter = "%sport %s )" % (filter, open_ports[-1])
        scapy.sniff(prn=self.pck_handler, filter=filter, timeout=self.timeout)

    # filtering for relevant packages
    def pck_handler(self, pkt):
        self.pck_counter = self.pck_counter + 1
        # looking for pkg that sent to my ip over tcp protocol
        if pkt.haslayer(IP) and pkt[IP].dst == self.ip:
            if pkt.haslayer(TCP):
                logging.info(f'attacker IP: {pkt[IP].src}, destination port: {pkt[TCP].dport}')

    def start(self):
        args = Namespace()
        args.ipslst = [self.ip]
        args.portslst = [1, 65535]
        args.network_id = None
        while True:
            open_ports = scanner.PortScanner(args).run()[self.ip]
            self.pck_counter = 0
            logging.info('started sniffing')
            self.sniffer(open_ports)
            logging.info(f"checked {self.pck_counter} packages.")
            sleep(self.period)


if __name__ == '__main__':
    PortDetector().start()
