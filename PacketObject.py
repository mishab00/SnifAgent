import mysql.connector


class PacketObject:
    packet = ''

    def __init__(self, packet_str):
        # print(dir(packet_str))
        print("****************FRAME DATA*************************")
        print(packet_str.sniff_time)
        print(packet_str.sniff_timestamp)
        print(packet_str.frame_info)
        print("****************END OF FRAME DATA*************************")
        self.packet = packet_str

    # 'pretty_print', 'raw_mode', 'src', 'src_ig', 'src_lg', 'src_oui', 'src_oui_resolved', 'src_resolved', 'type'
    def print_eth_values(self):
        print('addr', self.packet.eth.addr)
        # print('addr_oui', self.packet.eth.addr_oui)
        # print('addr_oui_resolved', self.packet.eth.addr_oui_resolved)
        # print('addr_resolved', self.packet.eth.addr_resolved)
        # print('dst', self.packet.eth.dst)
        # print('dst_oui_resolved', self.packet.eth.dst_oui_resolved)
        # print('dst_resolved', self.packet.eth.dst_resolved)
        # print('field_names', self.packet.eth.field_names)
        # print('ig', self.packet.eth.ig)
        # print('layer_name', self.packet.eth.layer_name)
        # print('lg', self.packet.eth.lg)
        # print('src', self.packet.eth.src)
        # print('src_ig', self.packet.eth.src_ig)
        # print('addr_oui', self.packet.eth.addr_oui)
        # print('src_lg', self.packet.eth.src_lg)
        # print('src_oui', self.packet.eth.src_oui)
        # print('src', self.packet.eth.src)
        # print('src_ig', self.packet.eth.src_ig)
        # print('src_oui_resolved', self.packet.eth.addr_oui)
        # print('src_lg', self.packet.eth.src_lg)
        # print('src_oui', self.packet.eth.src_oui)

    def print_ip_values(self):
        print("****************Parse IP Layer*************************")
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
        print("****************END IP Layer*************************")

    def print_tcp_values(self):
        try:
            # print('field_names', self.packet.tcp.field_names)
            print("****************Parse TCP Layer*************************")
            print('srcport', self.packet.tcp.srcport)
            print('dstport', self.packet.tcp.dstport)
            print('stream', self.packet.tcp.stream)
            print('len', self.packet.tcp.len)
            print('seq', self.packet.tcp.seq)
            # print('seq_raw', self.packet.tcp.seq_raw)
            print('nxtseq', self.packet.tcp.nxtseq)
            print('ack', self.packet.tcp.ack)
            # print('ack_raw', self.packet.tcp.ack_raw)
            print('hdr_len', self.packet.tcp.len)
            print('flags', self.packet.tcp.flags)
            print('flags_res', self.packet.tcp.flags_res)
            print('flags_ns', self.packet.tcp.flags_ns)
            print('flags_cwr', self.packet.tcp.flags_cwr)
            print('flags_ecn', self.packet.tcp.flags_ecn)
            print('flags_urg', self.packet.tcp.flags_urg)
            print('flags_ack', self.packet.tcp.flags_ack)
            print('flags_push', self.packet.tcp.flags_push)
            print('flags_reset', self.packet.tcp.flags_reset)
            print('flags_syn', self.packet.tcp.flags_syn)
            print('flags_fin', self.packet.tcp.flags_fin)
            print('flags_str', self.packet.tcp.flags_str)
            print('window_size_value', self.packet.tcp.window_size_value)
            print('window_size', self.packet.tcp.window_size)
            # print('window_size_scalefactor', self.packet.tcp.window_size_scalefactor)
            print('checksum', self.packet.tcp.checksum)
            print('checksum_status', self.packet.tcp.checksum_status)
            print('urgent_pointer', self.packet.tcp.urgent_pointer)
            print('time_relative', self.packet.tcp.time_relative)
            print('time_delta', self.packet.tcp.time_delta)

            print('payload', self.packet.tcp.payload)
        except AttributeError:
            print("")
        finally:
            print("****************END TCP Layer*************************")

    def print_http_response_values(self):
        try:
            print("****************Parse HTTP Response*************************")
            print("response_version", self.packet.http.response_version)
            print("response_for_uri", self.packet.http.response_for_uri)
            print("response_code", self.packet.http.response_code)
            print("response_code_desc", self.packet.http.response_code_desc)
            print("response_phrase", self.packet.http.response_phrase)
            print("response_line", self.packet.http.response_line)
            print("location", self.packet.http.location)
            print("set_cookie", self.packet.http.set_cookie)
            print("response", self.packet.http.response)
            print("response_number", self.packet.http.response_number)
            print("time", self.packet.http.time)

        except AttributeError:
            print("not http response")

        finally:
            print("****************END HTTP Response*************************")

    def print_http_request_values(self):
        try:
            print(dir(self.packet.http))
            print("****************Parse HTTP Request*************************")
            for field in self.packet.http._get_all_field_lines():
                print(field.strip())


            print("chat", self.packet.http.chat)
            # print("connection", self.packet.http.connection)
            print("get", self.packet.http.get)
            print("get_field", self.packet.http.get_field('X-Amz-Cf-Id'))
            print("get_field_by_showname", self.packet.http.get_field_by_showname('X-Amz-Cf-Id').show)
            print("get_field_value", self.packet.http.get_field_value)
            print("host", self.packet.http.host)
            print("layer_name", self.packet.http.layer_name)
            print("request", self.packet.http.request)

            print("request_full_uri", self.packet.http.request_full_uri)
            print("request_line", self.packet.http.request_line)
            print("request_method", self.packet.http.request_method)
            print("user_agent", self.packet.http.user_agent)
            print("request_number", self.packet.http.request_number)
            print("request_uri", self.packet.http.request_uri)
            #print("request_uri_path", self.packet.http.request_uri_path)
            #print("request_uri_query", self.packet.http.request_uri_query)
            #print("request_uri_query_parameter", self.packet.http.request_uri_query_parameter)
            print("request_version", self.packet.http.request_version)



        except AttributeError:
            print("not http request")

        finally:
            print("****************END HTTP Request*************************")

    def catch_http_request_values(self):
        try:
            print("****************Parse HTTP Request*************************")
            with open("test.csv", "a") as myfile:

                for field in self.packet.http._get_all_field_lines():
                    #every header is split by colon where left part is a title and right is value i need left part
                    if ':' in field and 'Expert Info' not in field and 'Severity level' not in field and 'Group' not in field:
                        keyValue = field.split(':', 1)
                        print(keyValue)
                        key = keyValue[0]
                        value = keyValue[1]
                        if "Request Method" in key:
                            myfile.write(value.strip() + ',')
                        elif "Request URI" in key:

                            myfile.write('num of path elements ' + str(len([v for v in value.strip().split("/") if v])) + ',')
                            myfile.write(value.strip() + ',')
                        elif "Full request URI" in key:
                            pass
                        elif "Request Version" in key:
                            myfile.write(value.strip() + ',')
                        elif "Prev request in frame" in key:
                            pass
                        elif "Request Version" in key:
                            pass
                        else:
                            myfile.write(key.strip() + ',')
                myfile.write("\n")

        except AttributeError:
            print("not http request")

        finally:
            print("****************END HTTP Request*************************")


    def connect_to_db(self):
        mydb = mysql.connector.connect(
            host="localhost",
            user="radware",
            password="washington",
            database="washington"
        )
        mycursor = mydb.cursor()
        # mycursor.execute("SHOW TABLES")
        sql = "INSERT INTO Agent (epoch, src_ip) VALUES (%s, %s)"
        val = (self.packet.sniff_timestamp, self.packet.ip.src)
        mycursor.execute(sql, val)
        mydb.commit()
        print(mycursor.rowcount, "record inserted.")
