#!/usr/bin/env python3
import pyshark
from PacketObject import PacketObject
from Buffer import Paraphrase, Buffer

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.


def start_sniffer():
    #capture = pyshark.LiveCapture(bpf_filter=name)
    capture = pyshark.FileCapture('windows_10_chrome.pcap')
    capture.set_debug()
    buffer = Buffer()
    for packet in capture:

        pkt = PacketObject(packet)
        #pkt.print_ip_values()
        #pkt.print_tcp_values()
        #pkt.print_http_response_values()
        #pkt.print_http_request_values()
        pkt.catch_http_request_values()
        para = Paraphrase(packet)
        para.parse_packet()
        if para.is_http_request:
            buffer.fill_buffer(para)
    buffer.save_to_file()
        #pkt.connect_to_db()




# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    start_sniffer()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
