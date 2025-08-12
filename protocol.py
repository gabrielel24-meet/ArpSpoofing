from scapy.all import srp
from scapy.layers.l2 import Ether, ARP
from mac_vendor_lookup import MacLookup


def scan_subnet(subnet):
    # Dictionary to store results
    devices = {}

    # Create ARP request
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send packet and get responses
    result = srp(packet, timeout=2, verbose=False)[0]

    for sent, received in result:
        mac = received.hwsrc
        try:
            vendor = MacLookup().lookup(mac)
        except:
            vendor = "Unknown"
        devices[received.psrc] = {"MAC": mac, "Vendor": vendor}
    return devices



if __name__ == "__main__":
    subnet = "192.168.1.1/24"
    devices = scan_subnet(subnet)

    print("Found devices:")
    for ip, mac in devices.items():
        print(f"{ip} → {mac}")
