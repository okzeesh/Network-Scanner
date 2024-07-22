
from scapy.all import ARP, Ether, srp
def scan_network(ip_range):
    try:
        # Create an ARP request packet
        arp_request = ARP(pdst=ip_range)
        # Create an Ethernet frame to broadcast the ARP request
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        # Combine the ARP request and Ethernet frame
        arp_request_broadcast = broadcast / arp_request

        # Send the packet and capture the response
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

        devices = []
        for sent, received in answered_list:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})

        return devices
    except Exception as e:
        print(f"An error occurred: {e}")
        return []                                                                                                                         
def print_devices(devices):
    if devices:
        print("IP Address\t\tMAC Address")
        print("-" * 40)
        for device in devices:
            print(f"{device['ip']}\t\t{device['mac']}")
    else:
        print("No devices found or an error occurred.")
# Input the IP range to scan
target_ip_range = input("Enter the IP range to scan (e.g., 192.168.1.1/24): ")

# Scan the network
devices = scan_network(target_ip_range)

# Print the results
print_devices(devices)