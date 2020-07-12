# Kotlin PCAP digester

## obtain test data
```
mkdir /tmp/pcap
sudo tcpdump -c10  -ilo -w/tmp/pcap/cap10.pcap  port 8080
sudo tcpdump -c50  -ilo -w/tmp/pcap/cap50.pcap  port 8080
sudo tcpdump -c100 -ilo -w/tmp/pcap/cap100.pcap port 8080
sudo tcpdump -c200 -ilo -w/tmp/pcap/cap200.pcap port 8080
```
