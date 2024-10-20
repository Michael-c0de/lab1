#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <windows.h>

static pcap_t *handle;
static u_char *out_f;
u_int64 count = 1;
void sync(void *arg);

// 数据包捕获回调函数
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{

    pcap_dump(out_f, pkthdr, packet);
    count++;
}

int main(char argc, char *argv[])
{
    setvbuf(stdout, NULL, _IONBF, 0);
    count = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *bpf_exp;
    if (argc < 3)
    {
        fprintf(stderr, "Usage %s:dev_name dump_file bpf_exp(optional)\n", argv[0]);
        fflush(stdout);
        return 0;
    }

    char *dev_name = argv[1];
    char *dump_file = argv[2];
    if (argc > 3)
    {
        bpf_exp = argv[3];
    }
    else
    {
        bpf_exp = "";
    }

    struct bpf_program bp;

    // 打开网络设备进行抓包
    handle = pcap_open_live(dev_name, 65536, 1, -1, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return 1;
    }

    if (pcap_compile(handle, &bp, bpf_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        fprintf(stderr, "pcap_compile: %s\n", bpf_exp);
        return 1;
    }

    if (pcap_setfilter(handle, &bp) == -1)
    {
        fprintf(stderr, "pcap_setfilter: %s\n", bpf_exp);
        return 1;
    }

    fprintf(stderr, "Capturing packets on device: %s\n", dev_name);

    out_f = (u_char *)pcap_dump_open(handle, dump_file);

    // 创建同步线程
    HANDLE syncHandle = (HANDLE)_beginthread(sync, 0, NULL);

    // 开始抓包并处理每个数据包
    pcap_loop(handle, 0, packet_handler, NULL);

    WaitForSingleObject(syncHandle, INFINITE);
    // 关闭设备
    pcap_close(handle);

    return 0;
}

void sync(void *arg)
{
    int message = 0;
    while (1)
    {
        scanf("%d", &message);
        switch (message)
        {
        case 1:
            printf("%llu\n", count);
            break;
        case 2:
            pcap_breakloop(handle);
            pcap_dump_flush(out_f);
            pcap_dump_close(out_f);
            return;
        default:
            break;
        }
    }
}
