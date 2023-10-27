from scapy.all import ARP, Ether, srp

def scan(ip):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def main():
    ip = "192.168.1.1/24"
    print("IP\t\t\tMAC Address")
    print("-----------------------------------------")
    devices = scan(ip)
    for device in devices:
        print(device['ip'] + "\t\t" + device['mac'])

if __name__ == "__main__":
    main()