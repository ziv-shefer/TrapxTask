import socket
import time
from ipaddress import *
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
import subprocess


class PortScanner:

    # setting default configuration file
    def cfg_handler(self):
        return {
            'ping': 'ping -c 1 -n 1 ',
            'network_id': '192.168.1.0/24',
            'ports_range': [1, 65535],
            'port_threading': 5000,
            'ip_threading': 50,
            'iplst': list(ip_network(self.network_id).hosts())
        }

    def __init__(self, cfg=None):
        if cfg is None:
            cfg = self.cfg_handler()
        self.ping = cfg['ping']
        self.network_id = cfg['network_id']
        self.ipsq = Queue()
        self.queuelst = []
        self.result = {}
        self.ports_range = cfg['ports_range']
        self.port_threading = cfg['port_threading']
        self.ip_threading = cfg['ip_threading']
        self.ipslst = cfg['ipslst']

    # pinging ips to identify if listening
    def ips_scanner(self, i):
        ip = str(i)
        res = subprocess.Popen(self.ping + ip, shell=True, stdout=subprocess.PIPE)
        (out, err) = res.communicate()
        if str(out).find('unreachable') < 0 and res.returncode == 0:
            self.ipsq.put(ip)
            print(f'the address {ip} is available')

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
                print("Port {} is open".format(port))
            s.close()
        except socket.error as exc:
            print(f"Caught exception socket.error : {exc}")

    #
    def ip_handler(self):
        while True:
            ip = self.ipsq.get()
            if ip:
                self.result[ip] = []
                qu = Queue()
                with ThreadPoolExecutor(self.port_threading) as executor:
                    for i in range(self.ports_range[0], self.ports_range[1]):
                        executor.submit(self.port_scanner, ip, i, qu)
                while qu.qsize() > 0:
                    self.result[ip].append(qu.get())
            else:
                break

    def run(self):
        t = time.time()
        # p = Process(target=self.ip_handler).start()
        with ThreadPoolExecutor(max_workers=self.ip_threading) as executor:
            executor.map(self.ips_scanner, self.ipslst)
        print('done with ips')
        self.ipsq.put(False)
        self.ip_handler()
        # while (p.is_alive()):
        #     time.sleep(5)
        print('done')
        print(time.time() - t)
        return self.result

# configuration file
cfg = {
    'ping': 'ping -c 1 -n 1 ',
    'network_id': '',
    'ports_range': [1, 65535],
    'port_threading': 5000,
    'ip_threading': 1,
    'ipslst': ['192.168.1.25', '192.168.1.23']
}

if __name__ == '__main__':
    PortScanner(cfg=cfg).run()
