from scapy.all import sniff, IP, TCP, UDP

def packet_analyze(packet):
    if IP in packet:
        print("Source IP:", packet[IP].src)
        print("Destination IP:", packet[IP].dst)

        if TCP in packet:
            print("Protocol: TCP")
        elif UDP in packet:
            print("Protocol: UDP")
        print("-" * 40)

sniff(prn=packet_analyze, count=10)
