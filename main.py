#!/usr/bin/env python3
import pyshark
from PacketObject import PacketObject

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.


def start_sniffer(name):
    capture = pyshark.LiveCapture(interface='ens192',bpf_filter=name)
    capture.set_debug()

    for packet in capture.sniff_continuously():

        pkt = PacketObject(packet)
        pkt.print_ip_values()
        pkt.connect_to_db()




# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    start_sniffer('tcp')

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
