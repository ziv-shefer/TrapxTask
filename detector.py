import logging
import os
from time import sleep
import scapy.all as scapy
from scapy.layers.inet import TCP, IP
import datetime
from scapy.layers.l2 import ARP, Ether


class PortDetector:
    _svc_name_ = "PortDetector"
    _svc_display_name_ = "Port Detector"

    def __init__(self):
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)  # or whatever
        handler = logging.FileHandler(r'C:\Users\zivsh\PythonProjects\TrapxTask\logs\12.log', 'w', 'utf-8')  # or whatever
        root_logger.addHandler(handler)
        self.ip = scapy.get_if_addr(scapy.conf.iface)
        self.syn_attack_counter = 0
        self.pck_counter = 0
        self.timeout = 10
        self.period = 60
        self.dir = os.path.dirname(os.path.realpath(__file__))

    def sniffer(self):
        scapy.sniff(prn=self.pck_handler, timeout=self.timeout)

    def syn_attack_detctor(self, pkt):
        try:
            if pkt[TCP].flags == 'S':
                sr_pkt = scapy.sr(IP(dst=pkt[IP].src)/TCP(dport=pkt[TCP].sport, flags='SA'), timeout=2)
                if len(sr_pkt[0].res) == 0:
                    self.syn_attack_counter = self.syn_attack_counter + 1
        except IndexError:
            pass

    def get_mac(self, ip):
        p = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip)
        result = scapy.srp(p, timeout=3, verbose=False)[0]
        return str(result[0][1].hwsrc)

    def arp_attack_detector(self, pkt):
        if pkt[ARP].op == 2:
            try:
                real_mac = self.get_mac(pkt[ARP].psrc)
                response_mac = pkt[ARP].hwsrc
                if real_mac != response_mac:
                    breakpoint()
                    logging.ERROR(f"[!] You are under arm attack, REAL-MAC: {real_mac.upper()}, FAKE-MAC: {response_mac.upper()}")
            except IndexError:
                pass

    def pck_handler(self, pkt):

        self.pck_counter = self.pck_counter + 1
        if pkt.haslayer(TCP):
            self.syn_attack_detctor(pkt)
        if pkt.haslayer(ARP):
            self.arp_attack_detector(pkt)

    def start(self):
        while True:
            self.syn_attack_counter = 0
            self.pck_counter = 0
            logging.info('start sniffing')
            self.sniffer()
            if self.syn_attack_counter * 2 >= self.pck_counter:
                logging.ERROR('[!] You are under syn-ack attack')
            logging.info(f"checked {self.pck_counter} packages.")
            sleep(self.period)


if __name__ == '__main__':
    PortDetector().start()
