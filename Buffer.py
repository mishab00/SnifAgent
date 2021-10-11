import re
import traceback

class Paraphrase:

    def __init__(self, packet_str):
        self.is_http_request = True
        self.packet = packet_str
        self.http_method = ""
        self.path_num = 0
        self.query_args_num = 0
        self.cookie_key_val_num = 0
        self.known_header_num = 0
        self.unknown_header_num = 0
        self.referrer_exist = None
        self.ua_exist = None
        self.accept_star_exist = None
        self.content_star_exist = None
        self.sec_star_exist = None
        self.if_star_exist = None
        self.authorization_exist = None
        self.cache_star_exist = None
        self.connection_exist = None
        self.host_exist = None
        self.date_exist = None
        self.pragma_exist = None
        self.known_header_list = ["accept*", "referer", "user-agent", "connection", "cache*", "host", "authorization",
                                  "content*", "sec-*", "if-*", "pragma", "a-im", "access-*", "date", "except",
                                  "forwarded", "from", "http2-settings", "max-forwards", "origin", "prefer",
                                  "proxy-authorization", "range", "te", "trailer", "transfer-encoding", "upgrade",
                                  "via", "warning"]
        self.all_headers_list = []

    def parse_packet(self):
        try:
            print(self.packet.http.request_method)
            if not self.packet.http.request_method:
                print("Packet without http header - bypass scan")
                self.is_http_request = False
                return
        except AttributeError:
            print("Packet without http header exception - bypass scan")
            self.is_http_request = False
            return

        try:
            for field in self.packet.http._get_all_field_lines():
                # every header is split by colon where left part is a title and right is value i need left part
                if ':' in field and 'Expert Info' not in field and 'Severity level' not in field and 'Group' not in field:
                    keyValue = field.split(':', 1)
                    #print(keyValue)
                    key = keyValue[0].strip()
                    value = keyValue[1]
                    if "Request Method" in key:
                        print("Request method " + value.strip())
                        if not value.strip():
                            print("WARNING " * 10)
                        self.http_method = value.strip()
                    elif "Request URI Query Parameter" in key:
                        self.query_args_num += 1
                    elif "Request URI" in key:
                        self.path_num = str(len([v for v in value.strip().split("/") if v]))
                    elif "Cookie pair" in key:
                        self.cookie_key_val_num += 1
                    elif "Cookie" in key:
                        pass
                    elif "Full request URI" in key:
                        pass
                    elif "Request Version" in key:
                        pass
                    elif "Prev request in frame" in key:
                        pass
                    elif "Content length" in key:
                        #wireshark print Content Lengh first and then the same value with lower case
                        pass
                    else:
                        self.all_headers_list.append(key.strip())
        except AttributeError:
            print(traceback.format_exc())

        finally:
            print("****************END HTTP Request*************************")
        # parse all headers and fill all relevant paraphrases
        # num of known headers
        for reg in self.known_header_list:
            r = re.compile(reg, re.IGNORECASE)
            newlist = list(filter(r.match, self.all_headers_list))
            #print(newlist)
            self.known_header_num += len(newlist)

        # num of unknown header
        self.unknown_header_num = len(self.all_headers_list) - self.known_header_num

        self.referrer_exist = True if "Referer" in self.all_headers_list else False
        self.ua_exist = True if "User-Agent" in self.all_headers_list else False

        r = re.compile("accept*", re.IGNORECASE)
        newlist = list(filter(r.match, self.all_headers_list))
        self.accept_star_exist = True if len(newlist) > 0 else False

        r = re.compile("content*", re.IGNORECASE)
        newlist = list(filter(r.match, self.all_headers_list))
        self.content_star_exist = True if len(newlist) > 0 else False

        r = re.compile("sec-*", re.IGNORECASE)
        newlist = list(filter(r.match, self.all_headers_list))
        self.sec_star_exist = True if len(newlist) > 0 else False

        r = re.compile("if-*", re.IGNORECASE)
        newlist = list(filter(r.match, self.all_headers_list))
        self.if_star_exist = True if len(newlist) > 0 else False

        self.authorization_exist = True if "authorization" in self.all_headers_list else False

        r = re.compile("cache*", re.IGNORECASE)
        newlist = list(filter(r.match, self.all_headers_list))
        self.cache_star_exist = True if len(newlist) > 0 else False

        self.connection_exist = True if "Connection" in self.all_headers_list else False
        self.host_exist = True if "Host" in self.all_headers_list else False
        self.date_exist = True if "Date" in self.all_headers_list else False
        self.pragma_exist = True if "Pragma" in self.all_headers_list else False


def add_buffer(buffer, value):
    counter = buffer.get(value, 0)
    counter += 1
    buffer[value] = counter


class Buffer:

    def __init__(self):
        self.total = 0
        self.http_methods = {}
        self.path_nums = {}
        self.known_header_nums = {}
        self.unknown_header_nums = {}
        self.query_args_num = {}
        self.key_value_cookie_nums = {}
        self.referer = {}
        self.ua = {}
        self.accept = {}
        self.content = {}
        self.sec = {}
        self.if_exist = {}
        self.authorization = {}
        self.cache = {}
        self.connection = {}
        self.host = {}
        self.date_exist = {}
        self.pragma = {}

    def fill_buffer(self, phrase):
        self.total += 1
        add_buffer(self.http_methods, phrase.http_method)
        add_buffer(self.path_nums, phrase.path_num)
        add_buffer(self.known_header_nums, phrase.known_header_num)
        add_buffer(self.unknown_header_nums, phrase.unknown_header_num)
        add_buffer(self.query_args_num, phrase.query_args_num)
        add_buffer(self.key_value_cookie_nums, phrase.cookie_key_val_num)
        add_buffer(self.referer, phrase.referrer_exist)
        add_buffer(self.ua, phrase.ua_exist)
        add_buffer(self.accept, phrase.accept_star_exist)
        add_buffer(self.content, phrase.content_star_exist)
        add_buffer(self.sec, phrase.sec_star_exist)
        add_buffer(self.if_exist, phrase.if_star_exist)
        add_buffer(self.authorization, phrase.authorization_exist)
        add_buffer(self.cache, phrase.cache_star_exist)
        add_buffer(self.connection, phrase.connection_exist)
        add_buffer(self.host, phrase.host_exist)
        add_buffer(self.date_exist, phrase.date_exist)
        add_buffer(self.pragma, phrase.pragma_exist)

    def save_to_file(self):
        with open("buffer.csv", "a") as f:
            f.write("Total packets " + str(self.total) + "\n")
            f.write("HTTP METHODS, ")
            for key in self.http_methods:
                f.write(str(key) + "=" + str(self.http_methods[key]) + ", ")
            f.write("\nNUM OF PATH ELEMENTS, ")
            for key in self.path_nums:
                f.write(str(key) + "=" + str(self.path_nums[key]) + ", ")

            f.write("\nNUM OF KNOWN HEADERS, ")
            for key in self.known_header_nums:
                f.write(str(key) + "=" + str(self.known_header_nums[key]) + ", ")

            f.write("\nNUM OF UNKNOWN HEADERS, ")
            for key in self.unknown_header_nums:
                f.write(str(key) + "=" + str(self.unknown_header_nums[key]) + ", ")

            f.write("\nNUM OF QUERY ARGS, ")
            for key in self.query_args_num:
                f.write(str(key) + "=" + str(self.query_args_num[key]) + ", ")

            f.write("\nNUM KEY VALUES IN COOKIE, ")
            for key in self.key_value_cookie_nums:
                f.write(str(key) + "=" + str(self.key_value_cookie_nums[key]) + ", ")

            f.write("\nreferer exist, ")
            for key in self.referer:
                f.write(str(key) + "=" + str(self.referer[key]) + ", ")

            f.write("\nUA exist, ")
            for key in self.ua:
                f.write(str(key) + "=" + str(self.ua[key]) + ", ")

            f.write("\naccept star exist, ")
            for key in self.accept:
                f.write(str(key) + "=" + str(self.accept[key]) + ", ")

            f.write("\ncontent star exist, ")
            for key in self.content:
                f.write(str(key) + "=" + str(self.content[key]) + ", ")

            f.write("\nsec star exist, ")
            for key in self.sec:
                f.write(str(key) + "=" + str(self.sec[key]) + ", ")

            f.write("\nif star exist, ")
            for key in self.if_exist:
                f.write(str(key) + "=" + str(self.if_exist[key]) + ", ")

            f.write("\nauthorization exist, ")
            for key in self.authorization:
                f.write(str(key) + "=" + str(self.authorization[key]) + ", ")

            f.write("\ncache star exist, ")
            for key in self.cache:
                f.write(str(key) + "=" + str(self.cache[key]) + ", ")

            f.write("\nconnection exist, ")
            for key in self.connection:
                f.write(str(key) + "=" + str(self.connection[key]) + ", ")

            f.write("\nhost exist, ")
            for key in self.host:
                f.write(str(key) + "=" + str(self.host[key]) + ", ")

            f.write("\ndate exist, ")
            for key in self.date_exist:
                f.write(str(key) + "=" + str(self.date_exist[key]) + ", ")

            f.write("\npragma exist, ")
            for key in self.pragma:
                f.write(str(key) + "=" + str(self.pragma[key]) + ", ")



