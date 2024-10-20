#!/usr/bin/env python3
import libpcap as pcap
import ctypes as ct
import socket

class PcapDeviceManager:
    def __init__(self):
        self.devices = None
        self.devices_name = None
    def find_all_devices(self):
        """Find and store all available devices."""
        # Create a buffer to store error messages
        errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)
        # Create a pointer to hold the list of devices
        alldevs = ct.POINTER(pcap.pcap_if_t)()
        # Call the pcap.findalldevs function to get all available devices
        if pcap.findalldevs(ct.byref(alldevs), errbuf) != 0:
            raise RuntimeError(f"Error finding devices: {errbuf.value.decode()}")
        self.devices = alldevs
        return alldevs

    def iter_parse(self, node, attrnames, top_one=False):
        """Parse a linked list of attributes and return them as a list."""
        attrs = []
        while node:
            tmp = [getattr(node.contents, attr) for attr in attrnames]
            if top_one:
                return tmp
            attrs.append(tmp)
            node = node.contents.next
        return [list(x) for x in zip(*attrs)]

    def get_one_ip_from_pcap_addr(self, addresse):
        """Get a single IP address from a pcap_addr structure."""
        sockaddr = self.iter_parse(addresse, ["addr"], top_one=True)
        if not sockaddr:
            return None
        [sockaddr] = sockaddr
        ipv4_addr = sockaddr.contents.ipv4_addr
        return socket.inet_ntoa(ipv4_addr)

    def list_devices(self):
        """Return a list of device descriptions and their first IP addresses."""
        if not self.devices:
            raise RuntimeError("No devices found. Call find_all_devices() first.")
        
        devices_info = []
        description, addresses, self.devices_name = self.iter_parse(self.devices, ["description", "addresses", "name"])
        for id, (des, ip) in enumerate(zip(description, addresses)):
            ip_address = self.get_one_ip_from_pcap_addr(ip)
            devices_info.append((id, des.decode(), ip_address))
        self.find_all_devices()
        return devices_info
    
    def get_device(self, target:int):
        return self.devices_name[target]

    def freealldevs(self):
        """Cleanup: free the devices list."""
        if self.devices:
            pcap.freealldevs(self.devices)


def select_device():
    """选择设备"""
    manager = PcapDeviceManager()
    manager.find_all_devices()    
    devices_info = manager.list_devices()
    for id, description, ip in devices_info:
        print(f"#{id}, {description}, {ip}")    
    a  = int(input("Please select a device: "))
    device = manager.get_device(a)
    return device


# 示例使用：
if __name__ == "__main__":
    manager = PcapDeviceManager()
    manager.find_all_devices()
    
    devices_info = manager.list_devices()
    for id, description, ip in devices_info:
        print(f"#{id}, {description}, {ip}")
    
    a  = int(input())
    device = manager.get_device(a)
    print(f"You select device {a},{device}")