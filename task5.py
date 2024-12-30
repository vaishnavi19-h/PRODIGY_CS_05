from scapy.all import sniff, IP, Raw

def packet_callback(packet):
    if IP in packet:  # Check if the packet has an IP layer
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")

        if Raw in packet:  # Check if the packet has a Raw layer (payload)
            payload = packet[Raw].load
            try:
                payload_decoded = payload.decode('utf-8', errors='replace')
                print(f"Payload: {payload_decoded}")
            except Exception as e:
                print(f"Payload (raw): {payload}")
        else:
            print("No payload found.")
    else:
        print("Not an IP packet.")

# Start sniffing packets
sniff(prn=packet_callback, store=0)