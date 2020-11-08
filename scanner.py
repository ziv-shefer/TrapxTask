import socket
import time
from ipaddress import *
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
import subprocess


class PortScanner:
    def __init__(self):
        self.ping = 'ping -c 1 -n 1 '
        self.network_id = '192.168.1.0/24'
        self.ipsq = Queue()
        self.queuelst = []
        self.result = {}

    def ips_scanner(self, ip):
        res = subprocess.Popen(self.ping + ip, shell=True, stdout=subprocess.PIPE)
        (out, err) = res.communicate()
        if str(out).find('unreachable') < 0 and res.returncode == 0:
            self.ipsq.put(ip)
            print(f'the adress {ip} is available')


    def port_scanner(self, ip, port, q:Queue):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                q.put(port)
                print("Port {} is open".format(port))
            s.close()
        except socket.error as exc:
            print(f"Caught exception socket.error : {exc}")

    def ip_handler(self):
        while(True):
            ip = self.ipsq.get()
            if ip:
                self.result[ip] = []
                qu = Queue()
                with ThreadPoolExecutor(5000) as executor:
                    for i in range(1, 65535):
                        executor.submit(self.port_scanner, ip, i, qu)
                while qu.qsize() > 0:
                    self.result[ip].append(qu.get())
            else:
                break
    def run(self):
        t = time.time()
        # p = Process(target=self.ip_handler).start()
        print('hi')
        le = list(ip_network(self.network_id).hosts())
        with ThreadPoolExecutor(max_workers=50) as executor:
            for i in le:
                executor.submit(self.ips_scanner, str(i))
        print('done with ips')
        self.ipsq.put(False)
        self.ip_handler()
        # while (p.is_alive()):
        #     time.sleep(5)
        print('done')
        print(time.time()-t)
        breakpoint()







example = PortScanner()
example.run()
