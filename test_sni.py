from scapy.all import IP, TCP, Raw, Ether
import re

# Sahte bir TLS Client Hello (SNI = sahibinden.com)
payload = b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03" + b"A"*32 + b"\x00\x00\x00\x00\x00\x12\x00\x00\x00\x0e\x00\x0c\x00\x00\x09sahibinden.com"

# Kaba bir regex
strings = re.findall(rb'[a-z0-9.-]+\.[a-z]{2,6}', payload.lower())
found = False
for s in strings:
    s_str = s.decode('utf-8', errors='ignore')
    if s_str.endswith(('.com', '.net', '.org', '.tr', '.io', '.co', '.dev', '.info', '.gov', '.edu')):
        print("FOUND:", s_str)
        found = True

if not found:
    print("NOT FOUND")
