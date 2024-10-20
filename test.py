import mmap
import os
import time
import subprocess
from device_mm import select_device
import ctypes as ct
# # 创建或连接到现有的共享内存块
# shared_memory_name = "Global\\my_shared_memory"
# shared_memory_size = 256  # 共享内存大小

# # 打开或创建映射
# hMapFile = mmap.mmap(-1, shared_memory_size, shared_memory_name)

# # 向C程序发送指令
# def send_signal(signal):
#     # 将指令写入共享内存
#     hMapFile.seek(0)
#     hMapFile.write(signal.encode('utf-8'))
#     hMapFile.flush()

# # 读取共享内存中的数据
# def read_signal():
#     hMapFile.seek(0)
#     return hMapFile.read(256).decode('utf-8').strip('\x00')

# # 发送指令给C程序
# print("Sending signal '1' to start counting packets...")
# send_signal("1")

# # 等待一段时间以模拟C程序开始抓包
# time.sleep(2)

# # 发送指令给C程序，告诉它停止抓包
# print("Sending signal '2' to stop capturing packets...")
# send_signal("2")

# # 关闭共享内存
# hMapFile.close()


dev = select_device()  # 选择设备
bpf = ""
out_file = "tmp.pcap"
# 启动子进程，并创建新控制台
process = subprocess.Popen(
    args=["D:\\2024fall\\lab1\\packet_ana\\build\\Release\\main.exe", dev, out_file, bpf],
    creationflags=subprocess.CREATE_NEW_CONSOLE,
    stdin=subprocess.PIPE, 
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    )
try:
    while True:
        # 写入子进程的 stdin，模拟发送数据
        process.stdin.write("1\n")
        process.stdin.flush()  # 刷新缓冲区，确保数据立即发送到子进程

        # 读取子进程的 stdout
        output = process.stdout.readline().strip()

        print(int(output))
        time.sleep(1)

except Exception as e:
    print(f"错误: {e}")

finally:
    # 确保子进程被正确终止
    process.terminate()
    process.wait()