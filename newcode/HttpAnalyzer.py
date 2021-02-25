
import dpkt
import socket
from os import listdir
from os.path import isfile, join
import string
from EntropyCalculator import *


class HttpAnalyzer :
    def __init__(self, pathtoFolder, classification,outfilepathName):
        self.files = []
        self.ReqHeaders = {}
        self.RespHeaders = {}
        self.HostUri = {}
        self.classification = ""
        if len(pathtoFolder) > 0 :
            self.files = [join(pathtoFolder,f) for f in listdir(pathtoFolder) if isfile(join(pathtoFolder,f))]
            print(self.files)
        self.outfile =  open(outfilepathName, "w")
        
    def ExtractFromPcap(self, func):    
        for fil in self.files:
            f = open(fil)
            try :
                pcap = dpkt.pcap.Reader(f)
                self.ExtractInfoFromPcap(pcap, func)
            except :
                pass
            f.close()
        print "Done parsing"
        self.outfile.close()
     
    def ExtractInfoFromPcap(self, pcap, func): 
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                ip = eth.data 
                if ip.p == dpkt.ip.IP_PROTO_TCP:  
                    tcp = ip.data
                    if (tcp.dport == 80 or tcp.dport== 443) and len(tcp.data) > 0:
                        try:
                            http_req = dpkt.http.Request(tcp.data)
                            func(http_req)
                            continue
                        except:
                            pass    
                        try:
                            http_resp = dpkt.http.Response(tcp.data)
                            func(http_resp)
                        except:
                            pass
                        
    def ListReqBodyEntropy(self, http_req):
        if(len(http_req.body) > 0) :
            (l,h) = hist(http_req.body)
            s = entropy(h, l)
            self.outfile.write( str(s))
            self.outfile.write ("\n")
                            
    def ListURIEntropy(self, http_req):
        if len(http_req.uri) :
            (l,h) = hist(http_req.uri);
            s = entropy(h, l)
            self.outfile.write( str(s))
            self.outfile.write ("\n") 
            '''self.outfile.write(http_req.uri + " : " + http_req.headers["host"]) 
            self.outfile.write ("\n") 
            self.outfile.write(http_req.method + " : " + http_req.body )
            self.outfile.write ("\n")''' 
        else :
            print "Uri not found"
        
    def ListAllDistinctRequestHeadersFound(self, http_req): 
        for key in http_req.headers:
            if key in self.ReqHeaders : 
                self.ReqHeaders[key] += 1
            else :
                self.ReqHeaders[key] = 1
    
    def ListAllDistinctResponseHeadersFound(self, http_resp):
        if  "Version " + http_resp.version in self.RespHeaders :
            self.RespHeaders["Version " + http_resp.version] += 1
        else :
            self.RespHeaders["Version " + http_resp.version] = 1
        if  "Status " + http_resp.status in self.RespHeaders :
            self.RespHeaders["Status " + http_resp.status] += 1
        else :
            self.RespHeaders["Status " + http_resp.status] = 1
        if  "Reason " + http_resp.reason in self.RespHeaders :
            self.RespHeaders["Reason " + http_resp.reason] += 1
        else :
            self.RespHeaders["Reason " + http_resp.reason] = 1
                    
                    
#Get good and bad body entropy
p = HttpAnalyzer("/home/sakella/examples/pcaps_good","B", "/home/sakella/examples/goodreqbodyEnt.txt")
p.ExtractFromPcap(p.ListReqBodyEntropy)
del p
p = HttpAnalyzer("/home/sakella/examples/pcaps_bad","M", "/home/sakella/examples/bodreqbodyEnt.txt")
p.ExtractFromPcap(p.ListReqBodyEntropy)
del p 
# get good and bad uri entropy
p = HttpAnalyzer("/home/sakella/examples/pcaps_good","B", "/home/sakella/examples/goodURIEnt.txt")
p.ExtractFromPcap(p.ListURIEntropy)
del p
p = HttpAnalyzer("/home/sakella/examples/pcaps_bad","M", "/home/sakella/examples/badURIEnt.txt")
p.ExtractFromPcap(p.ListURIEntropy)
del p
