from scapy.all import *

pkts = rdpcap("<test_pcap>")

nic1 = "<nic1>"
nic2 = "<nic2>"

nic1_ip = "<nic1_ip>"
nic2_ip = "<nic2_ip>"

mac1 = get_if_hwaddr(nic1)
mac2 = get_if_hwaddr(nic2)

src_ip_from_first_pcap = pkts[0][IP].src
dest_ip_from_first_pcap = pkts[0][IP].dst

ip_id = 55688

# 修改封包中的 IP 和 MAC 位址
for pkt in pkts:
    
    if pkt[IP].src == src_ip_from_first_pcap:

        if IP in pkt:
            pkt[IP].src = nic1_ip
            pkt[IP].dst = nic2_ip
            pkt[IP].id = ip_id

        if Ether in pkt:
            pkt[Ether].src = mac1
            pkt[Ether].dst = mac2

        del pkt[IP].chksum
        del pkt[TCP].chksum
        # pkt.show()

        # 發送封包
        sendp(pkt, iface= nic1)
        ip_id += 1

    elif pkt[IP].src == dest_ip_from_first_pcap:
        if IP in pkt:
            pkt[IP].src = nic2_ip
            pkt[IP].dst = nic1_ip
            pkt[IP].id = ip_id

        if Ether in pkt:
            pkt[Ether].src = mac2
            pkt[Ether].dst = mac1

        del pkt[IP].chksum
        del pkt[TCP].chksum
        # pkt.show()
        # 發送封包
        sendp(pkt, iface= nic2)
        ip_id += 1
