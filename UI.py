import tkinter as tk
from tkinter import messagebox
from scapy.all import srp
from scapy.layers.l2 import Ether, ARP
from mac_vendor_lookup import MacLookup
from SpoofingGPT import Start

def scan_subnet(subnet):
    devices = {}
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=False)[0]

    for sent, received in result:
        mac = received.hwsrc
        try:
            vendor = MacLookup().lookup(mac)
        except:
            vendor = "Unknown"
        devices[received.psrc] = {"MAC": mac, "Vendor": vendor}
    return devices


class ScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Scanner")

        self.scan_button = tk.Button(self, text="Scan", command=self.start_scan)
        self.scan_button.pack(pady=10)

        self.devices_frame = tk.Frame(self)
        self.devices_frame.pack(pady=10)

    def start_scan(self):
        self.scan_button.config(state=tk.DISABLED)
        for widget in self.devices_frame.winfo_children():
            widget.destroy()

        try:
            devices = scan_subnet("192.168.1.1/24")
            if not devices:
                messagebox.showinfo("Scan Result", "No devices found.")
            else:
                for ip, info in devices.items():
                    btn_text = f"{ip} - {info['Vendor']}"

                    # Define the callback with default arg trick to capture current ip/info
                    def on_button_click(ip=ip, info=info):
                        self.device_button_clicked(ip, info)

                    btn = tk.Button(self.devices_frame, text=btn_text, command=on_button_click)
                    btn.pack(fill='x', padx=5, pady=2)
        except Exception as e:
            messagebox.showerror("Error", str(e))
        finally:
            self.scan_button.config(state=tk.NORMAL)

    def device_button_clicked(self, ip, info):
        # This function runs when you click a device button
        Start(ip)

if __name__ == "__main__":
    app = ScannerApp()
    app.mainloop()
