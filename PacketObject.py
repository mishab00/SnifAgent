import mysql.connector
class PacketObject:
    packet = ''

    def __init__(self, packet_str):
        print(dir(packet_str))
        print(packet_str.sniff_time)
        print(packet_str.sniff_timestamp)
        print(packet_str.frame_info)

        self.packet = packet_str

# 'pretty_print', 'raw_mode', 'src', 'src_ig', 'src_lg', 'src_oui', 'src_oui_resolved', 'src_resolved', 'type'
    def print_eth_values(self):
        print('addr', self.packet.eth.addr)
        print('addr_oui', self.packet.eth.addr_oui)
        print('addr_oui_resolved', self.packet.eth.addr_oui_resolved)
        print('addr_resolved', self.packet.eth.addr_resolved)
        print('dst', self.packet.eth.dst)
        print('dst_oui_resolved', self.packet.eth.dst_oui_resolved)
        print('dst_resolved', self.packet.eth.dst_resolved)
        print('field_names', self.packet.eth.field_names)
        print('ig', self.packet.eth.ig)
        print('layer_name', self.packet.eth.layer_name)
        print('lg', self.packet.eth.lg)
        print('src', self.packet.eth.src)
        print('src_ig', self.packet.eth.src_ig)
        print('addr_oui', self.packet.eth.addr_oui)
        print('src_lg', self.packet.eth.src_lg)
        print('src_oui', self.packet.eth.src_oui)
        print('src', self.packet.eth.src)
        print('src_ig', self.packet.eth.src_ig)
        print('src_oui_resolved', self.packet.eth.addr_oui)
        print('src_lg', self.packet.eth.src_lg)
        print('src_oui', self.packet.eth.src_oui)

    def print_ip_values(self):
        print('src', self.packet.ip.src)
        print('dst', self.packet.ip.dst)
        print('checksum', self.packet.ip.checksum)
        print('checksum_status', self.packet.ip.checksum_status)
        print('dsfield', self.packet.ip.dsfield)
        print('dsfield_dscp', self.packet.ip.dsfield_dscp)
        print('dsfield_ecn', self.packet.ip.dsfield_ecn)
        print('dst_host', self.packet.ip.dst_host)
        print('field_names', self.packet.ip.field_names)
        print('flags', self.packet.ip.flags)
        print('flags_df', self.packet.ip.flags_df)
        print('flags_mf', self.packet.ip.flags_mf)
        print('flags_rb', self.packet.ip.flags_rb)
        print('frag_offset', self.packet.ip.frag_offset)
        print('hdr_len', self.packet.ip.hdr_len)
        print('host', self.packet.ip.host)
        print('id', self.packet.ip.id)
        print('layer_name', self.packet.ip.layer_name)
        print('len', self.packet.ip.len)
        print('proto', self.packet.ip.proto)
        print('src_host', self.packet.ip.src_host)
        print('ttl', self.packet.ip.ttl)
        print('version', self.packet.ip.version)

    def connect_to_db(self):
        cnx = mysql.connector.connect(
            host="localhost",
            user="radware",
            password="washington",
            database="washington"
        )
        mycursor = mydb.cursor()
        mycursor.execute("SHOW TABLES")

        for x in mycursor:
            print(x)
