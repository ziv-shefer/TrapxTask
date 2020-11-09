import logging
import os
from time import sleep, strftime, gmtime
import scapy.all as scapy
from scapy.layers.inet import TCP, IP, UDP
import datetime
from scapy.layers.l2 import ARP, Ether


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
        self.timeout = 10
        self.period = 60

    # sniffing the network with given timeout
    # passing all packages to pck_handler
    def sniffer(self):
        scapy.sniff(prn=self.pck_handler, timeout=self.timeout)

    # filtering for relevant packages
    def pck_handler(self, pkt):
        self.pck_counter = self.pck_counter + 1
        # looking for pkg that sent to my ip over tcp protocol
        if pkt.haslayer(IP) and pkt[IP].dst == self.ip:
            if pkt.haslayer(TCP):
                logging.info(f'sender IP: {pkt[IP].src}, sender port: {pkt[TCP].sport}')

    def start(self):
        while True:
            self.pck_counter = 0
            logging.info('started sniffing')
            self.sniffer()
            logging.info(f"checked {self.pck_counter} packages.")
            sleep(self.period)


if __name__ == '__main__':
    PortDetector().start()
