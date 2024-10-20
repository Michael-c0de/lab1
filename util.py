import libpcap as pcap
import ctypes as ct
# 深拷贝 pkthdr 结构体
def copy_pkthdr_pointer(_pkthdr):
    # 创建新的 pkthdr 对象，并复制字段
    new_pkthdr = pcap.pkthdr()
    ct.pointer(new_pkthdr)[0] = _pkthdr.contents  # 深拷贝结构体
    return ct.pointer(new_pkthdr)  # 返回新的指针

# 深拷贝 ct.POINTER(ct.c_ubyte) 类型的指针数据
def copy_packet_pointer(_packet, length):
    # 创建新的缓冲区，并将原始数据拷贝到新的缓冲区
    new_packet = (ct.c_ubyte * length)()  # 创建新的数组
    ct.memmove(new_packet, _packet, length)  # 深拷贝原始数据
    return ct.cast(new_packet, ct.POINTER(ct.c_ubyte))  # 返回新的指针


def hexdump_bytes(data):
    result = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f"{byte:02x}" for byte in chunk)
        ascii_part = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in chunk)
        result.append(f"{i:08x}  {hex_part:<47}  {ascii_part}")
    return '\n'.join(result)


def packet2dict(packet):
    display = {}
    p = packet
    while p:
        display[p.name] = p.fields
        p = p.payload
    return display

from scapy.all import *
def check_bpf_filter_validity(bpf_filter):
    try:
        # 使用 scapy 的 sniff 方法来应用 BPF 过滤器
        sniff(filter=bpf_filter, count=1, timeout=1)  # 捕获 1 个包，超时时间为 1 秒
        return True
    except Exception as e:
        return False