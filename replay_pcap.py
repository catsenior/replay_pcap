from scapy.all import *
import time, sys

pkts = rdpcap("<test_pcap>")

nic1 = "<nic1>"
nic2 = "<nic2>"

nic1_ip = "<nic1_ip>"
nic2_ip = "<nic2_ip>"

mac1 = get_if_hwaddr(nic1)
mac2 = get_if_hwaddr(nic2)
# dut_mac = "<dut_mac>"

client_port = pkts[0][TCP].sport
server_port = <server_port>

src_ip_from_first_pcap = pkts[0][IP].src
dest_ip_from_first_pcap = pkts[0][IP].dst

ip_id = 55688

# 3-way handshake

# SYN
syn_pkt = Ether(src= mac1, dst= mac2) / IP(src= nic1_ip, dst= nic2_ip) / TCP(sport= client_port, dport= server_port, flags='S')
sendp(syn_pkt, iface= nic1)
# SYN ACK
syn_ack_pkt = Ether(src= mac2, dst= mac1) / IP(src= nic2_ip, dst= nic1_ip) / TCP(sport= server_port, dport= client_port, flags='SA')
sendp(syn_ack_pkt, iface= nic2)
# ACK
ack_pkt = Ether(src= mac1, dst= mac2) / IP(src= nic1_ip, dst= nic2_ip) / TCP(sport= client_port, dport= server_port, flags='A')
sendp(ack_pkt, iface= nic1)

# 修改封包中的 IP 和 MAC 位址
for pkt in pkts:
    if pkt[IP].src == src_ip_from_first_pcap:
        if TCP in pkt:
            # 不進行 3-way handshake的話，必須先將 TCP flag 設定為 SYN，否則會被 DoS 功能阻擋。
            # seq, ack 不設定為 0，則會被視為攻擊封包，ubuntu系統不收。
            # pkt[TCP].flags = "S"
            # pkt[TCP].seq = 0
            # pkt[TCP].ack = 0
            pkt[TCP].dport = server_port

        if IP in pkt:
            pkt[IP].src = nic1_ip
            pkt[IP].dst = nic2_ip
            pkt[IP].id = ip_id

        if Ether in pkt:
            pkt[Ether].src = mac1
            # pkt[Ether].dst = dut_mac # Router mode
            pkt[Ether].dst = mac2

        del pkt[IP].chksum
        del pkt[TCP].chksum
        # pkt.show()

        # 發送封包
        sendp(pkt, iface= nic1)
        ip_id += 1
    elif pkt[IP].src == dest_ip_from_first_pcap:
        if TCP in pkt:
            # pkt[TCP].flags = "A"
            # pkt[TCP].seq = 0
            # pkt[TCP].ack = 0
            pkt[TCP].sport = server_port

        if IP in pkt:
            pkt[IP].src = nic2_ip
            pkt[IP].dst = nic1_ip
            pkt[IP].id = ip_id

        if Ether in pkt:
            pkt[Ether].src = mac2
            # pkt[Ether].dst = dut_mac # Router mode
            pkt[Ether].dst = mac1

        del pkt[IP].chksum
        del pkt[TCP].chksum
        # pkt.show()
        # 發送封包
        sendp(pkt, iface= nic2)
        ip_id += 1
