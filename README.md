#### **PORT SCANNER**

**SCANNER**

1. **main** - calling to PORT SCANNER class and takes
3 optional arguments (ports range, ips list, network id)
 from the user (by using argparse library).\
 after the scanning finish - main function prints the results.
 
 2. **init** - initialing the user output, or forging
 them by using scapy library.
 
 3. **ips scanner** - pinging one ip at a time 
 with arp ping using scapy,
 scapy arp ping output is two objects contains - 
 respond and unrespond,
 by measuring the number of responses (that supposed to be one)
 we can determine if the ip exist.
 
 4. **port scanner** - check if the port is active
 by sending a socket stream and wait for a response.
 
 5. **ip handler** - waits to new ip to be found in order
 to activate threadpool that will execute port scanner for
  checking all his open ports
 
 6. **run** - executing ips scanner using threadpool
 in order to find available ips, after finish executing
 ip handler and later return the results.       
 
 
 **DETECTOR**
 
 1. **init** - initializing logs infrastructure set 
 the frequency the service will sniff the network.
 
 2. **sniffer** - gets all the open ports on the machine
 and sniffing for 1 minute all packets that uses
 tcp on given ports - sending each package to
  pck handler for further research
  
  3. **pck handler** - for each package checking
  destination ip sender ip and the existence of
  tcp protocol - if the package answers al the
  requirements the connection will be added to the
  log file.
  
  4. **start** - initiate and execute scanner script,
  and uses his listening ports list to filter while sniffing,
  print the number of packages been checked, and sleep
  for 1 minute after finish sniffing.   