# replay_pcap

This script is primarily used for replaying network traffic. It reads packets from a pcap file and sends them out on a specified network interface.

## Features

- **Packet Replay**: The script reads packets from a pcap file and sends them out on a specified network interface. This can be used to reproduce network scenarios or test network devices.

- **IP and MAC Address Modification**: The script modifies the source and destination IP and MAC addresses of the packets before sending them out. This allows the replayed packets to appear as if they are coming from a different network device.

- **Automatic Handshake for Pure Packets**: If a packet is identified as a pure packet, the program can automatically complete the three-way handshake using the first packet.

## Usage

To use this script, you need to specify the pcap file to replay and the network interface to send the packets out on. You also need to specify the source and destination IP and MAC addresses to use for the replayed packets.

```python
sudo python replay_pcap_3W.py 
```

```python
sudo python change_ip_mac.py 
```
Please note that this script requires root privileges to send packets on a network interface.

## Checking

To check if the packets are being sent correctly, you can use the `tcpdump` command. This command will capture and display the packets on the network interface that match the specified condition. In this case, we are looking for packets with an IP ID of 55688.

```bash
sudo tcpdump -i <nic2> -n 'ip[4:2] == 55688'
```

Please replace `<nic2>` with the name of your network interface.
