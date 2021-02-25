#!/usr/bin/env python
import dpkt
import socket
from os import listdir
from os.path import isfile, join
import string
import NaiveBayes
import binascii
import time

class PcapDataProcessor (object) :
    def  __init__(self, name):
        self.name = name
        
    def ProcessData(self):
        raise NotImplementedError("Base class can't be used directly")
    
    def done(self):
        raise NotImplementedError("Base class can't be used directly")
    
class PcapFileDataProcessor (PcapDataProcessor) :
    def __init__(self, outfilepathName):
        self.outfile =  open(outfilepathName, "w")
        super(PcapFileDataProcessor, self).__init__("FileDataProcessor")
        
    def ProcessData(self, vector):        
        self.outfile.write('\t'.join(map(str, vector)))
        self.outfile.write ("\n")   
    
    def done(self):
        self.outfile.close()

class PcapStreamDataProcessor (PcapDataProcessor):
    def __init__(self,inputfolder, columnFormat):
        super(PcapStreamDataProcessor, self).__init__("StreamDataProcessor")
        self.c = NaiveBayes.Classifier(inputfolder, 0, columnFormat)
        
    def ProcessData(self, vector):        
        print "CLASSIFICATION DATA \n"
        res = self.c.classify(vector,[])
        print vector, "Result : ", res
        
    def done(self):
        print "Done Classification."

class PcapProcessor:
    
    def __init__(self, pathtoFolder, classification, dataProcessor):
        self.files = []
        self.vector = []
        self.netdata = []
        self.classification = ""
        if len(pathtoFolder) > 0 :
            self.files = [join(pathtoFolder,f) for f in listdir(pathtoFolder) if isfile(join(pathtoFolder,f))]
            print(self.files)
            self.classification = classification
        self.writer = dataProcessor
        
    def ExtractFromPcap(self):    
        for fil in self.files:
            f = open(fil)
            try :
                pcap = dpkt.pcap.Reader(f)
                totals = self.ExtractEachEntry(pcap)
                print fil, totals
            except :
                pass
            f.close()
        self.writer.done()
        
    def ExtractEachEntry(self, pcap): 
        totals = []
        totallines = 0;
        totalhttp = 0;     
        for ts, buf in pcap:
            totallines += 1
            totalhttp+= self.ExtractFromBuffer(buf)
        #print totallines, totalhttp
        totals.append(totallines)
        totals.append(totalhttp)
        return totals  
    
    # ######## HM eth address to ASCII notation 
    def add_colons_to_mac(self, mac_addr):
    	#"""This function accepts a 12 hex digit string and converts it to a colon separated string"""
        s = list()
        for i in range(12/2) : 	# mac_addr should always be 12 chars, we work in groups of 2 chars
            s.append( mac_addr[i*2:i*2+2] )
    	#I know this looks strange, refer to http://docs.python.org/library/stdtypes.html#sequence-types-str-unicode-list-tuple-bytearray-buffer-xrange
        r = ":".join(s) 
        return r
    # HM 
    # vector will have following columns  IP_Reputation   Has HTTP header     Domain_Reputation  Cookie present or NOT     Has Referrer or NOT    http method  URI String <= 10 character    URI String > 10 <=50    URI String > 50 <=100    URI String > 100    URI has js     (GET Header has x-flash-version:Dont know how to get this??)    URI has jquery    URI has overload ?swf    URI has XSS    URI has GIF/Jpg/png    URI has callback JSON (dont know how to do this ??)    URI has DLL    URI has rar    GET has overloaded mp3    URI has overloaded silverlight exploit - XAP(dont know how to do this???)    URI has jar    URI has any SQL command     TCP Window Size Scaling Factor (-ve  (Dont know how to do this ??)     TCP Options    
    # Will be implemented later   Packet Size    ARP     Looking for Multicast IP    DNS    HTTP Header present (Yes/NO)    HTTP details (what all)    Chat protocol    C2 Commands    ADSPACE comments??    GIF headers    Class (M/NM)
    # At end of Extract each entry, it will be pushed down into the file.

    def ExtractFromBuffer(self, buf, macint):
        ret = 0; 
        #print "Mac address interface" + macint
        eth = dpkt.ethernet.Ethernet(buf)
        eth_src = self.add_colons_to_mac(binascii.hexlify(eth.src))
        eth_dst = self.add_colons_to_mac(binascii.hexlify(eth.dst))
        # HM the src eth addr needs to be Interface Mac addr, if this is the case then it is egress. The if control can be fixed.. not now
        # Need to look for only egress traffic
        if (eth_dst == macint):
           #print "PKT Mac address DST: " + eth_dst
           #print "PKT Mac address SRC: " + eth_src
           return ret
        # Ethernet data 
        ts = time.time()
        
        self.netdata.append(ts)
        self.netdata.append(eth_src)
        self.netdata.append(eth_dst)
        self.netdata.append(eth.type)
        # Ethernet Data

        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data 

            # IP DATA
            dst_ip_addr_str = socket.inet_ntoa(ip.dst)
            src_ip_addr_str = socket.inet_ntoa(ip.src)
            self.netdata.append(ip.id)
            self.netdata.append(dst_ip_addr_str)
            self.netdata.append(src_ip_addr_str)
            self.netdata.append(ip.hl)
            self.netdata.append(ip.len)
            self.netdata.append(ip.p)
            self.netdata.append(ip.tos)
            #IP END DATA
            # Later do for UDP as well 
 
            if ip.p == dpkt.ip.IP_PROTO_TCP:  
                tcp = ip.data

                # TCP Data 
                self.netdata.append(tcp.dport)
                self.netdata.append(tcp.sport)
                iphdrlen = ip.hl*4
                tcpoffset = tcp.off*4
                #print "the IP TOTAL LEN  %d" % ip.len
                #print "IP HL %d "  % iphdrlen 
                #print "TCP Offset %d "  % tcpoffset 
                tcppayload = ip.len - (iphdrlen + tcpoffset) 
                self.netdata.append(tcppayload)
                self.netdata.append(tcp.flags)
                self.netdata.append(tcp.win)
                self.netdata.append(tcp.ack)
                self.netdata.append(tcp.seq)
                #if (tcppayload > 0) :
                    #print ','.join(map(str, self.netdata))
                #print "TCP packet size  %d" % tcppayload
                # TCP END DATA

                try:
                    if (tcp.dport == 80 or tcp.dport== 443) and len(tcp.data) > 0:
                        http_req = dpkt.http.Request(tcp.data)

                        # HTTP DATA 
                        self.netdata.append(http_req.headers)
                        self.netdata.append(http_req.method)
                        self.netdata.append(http_req.version)
                        if (http_req.method == "POST") :
                           self.netdata.append(http_req.body)
                        self.netdata.append("\n")
                        print "PACKET DETAILS L2-L7 \n"
                        print ','.join(map(str, self.netdata))
                        #print "the HTTP req headers %s"  % http_req.headers 
                        #print "the HTTP req METHOD %s"  % http_req.method 
                        # HTTP END DATA 

                        self.GetIPReputation(eth.ip.dst)  
                        self.ExtractHttpHeaderInfo(http_req)    
                        self.vector.append(http_req.method)
                        self.ExtractURIInfo(http_req)    
                        if len(http_req.data) > 0:
                            if not self.istext(http_req.data) :
                                self.vector.append("binary")
                            else :
                                self.vector.append("text")
                        else :
                            self.vector.append("none")
                        if(self.classification is not "") :
                            self.vector.append(self.classification)
                        #print http_req.uri
                        #print '\t'.join(map(str, self.vector))
                        self.writer.ProcessData(self.vector) 
                        del self.vector[:]
                        ret = 1
                except:
                    pass               
        del self.netdata[:]
        return ret
          
    def GetIPReputation(self, ip):
        #print (socket.inet_ntoa(ip))
        self.vector.append("unkip")
    
    def GetDomainReputation(self, domain):
        #print (domain)
        if self.classification == "M" :
            self.vector.append("bad")
        else :
            self.vector.append("unkdom")
    
    def ExtractHttpHeaderInfo(self, http_req):
        #print http_req.headers.keys()
        #print http_req.headers
            if len(http_req.headers.keys()) > 0:
                self.vector.append("yes")
            else :
                self.vector.append("no")
            if http_req.headers["host"] :
                self.GetDomainReputation( http_req.headers["host"])
            try :
                if http_req.headers["cookie"] :
                    self.vector.append("yes")
            except KeyError:
                self.vector.append("no")
            try :
                if http_req.headers["referer"] :  
                    self.vector.append("yes")
            except KeyError:
                self.vector.append("no")
             
    def ExtractURIInfo(self, http_req):
        if len(http_req.uri) <= 10:
            self.vector.append("yes")
        else:
            self.vector.append ("no")
        if len(http_req.uri) > 10 and len(http_req.uri) <= 50:
            self.vector.append("yes")
        else:
            self.vector.append ("no")
        if len(http_req.uri) > 50 and len(http_req.uri) <= 100:
            self.vector.append("yes")
        else:
            self.vector.append ("no")
        if len(http_req.uri) > 100:
            self.vector.append("yes")
        else:
            self.vector.append ("no")
        if ".js" in http_req.uri :
            self.vector.append("yes")
        else:
            self.vector.append ("no")
        if ".jquery" in http_req.uri :
            self.vector.append("yes")
        else:
            self.vector.append ("no")
        if "?swf" in http_req.uri :
            self.vector.append("yes")
        else:
            self.vector.append ("no")
        if "XSS" in http_req.uri :
            self.vector.append("yes")
        else:
            self.vector.append ("no")
        if ".jif" in http_req.uri.lower() or ".jpg" in http_req.uri.lower() or ".png" in http_req.uri.lower() or ".jpeg" in http_req.uri.lower():
            self.vector.append("yes")
        else:
            self.vector.append ("no")
        if ".dll" in http_req.uri :
            self.vector.append("yes")
        else:
            self.vector.append ("no")
        if ".rar" in http_req.uri :
            self.vector.append("yes")
        else:
            self.vector.append ("no")
        if ".mp3" in http_req.uri :
            self.vector.append("yes")
        else:
            self.vector.append ("no")
        if ".jar" in http_req.uri :
            self.vector.append("yes")
        else:
            self.vector.append ("no")
        if "select " in http_req.uri.lower() or "insert " in http_req.uri.lower() or "update " in http_req.uri.lower() or "delete " in http_req.uri.lower():
            self.vector.append("yes")
        else:
            self.vector.append ("no")

    # this method has been copied from internet, It is for identifying if the data along with get or post is binary or text.
    def istext(self, s):
        text_characters = "".join(map(chr, range(32, 127)) + list("\n\r\t\b"))
        _null_trans = string.maketrans("", "")
        if "\0" in s:
            return 0
        if not s:  # Empty files are considered text
            return 1
        # Get the non-text characters (maps a character to itself then
        # use the 'remove' option to get rid of the text characters.)
        t = s.translate(_null_trans, text_characters)
        # If more than 30% non-text characters, then
        # this is considered a binary file
        if float(len(t))/len(s) > 0.30:
            return 0
        return 1
          
# the constructor of PcapProcessor takes the following params
# (a) folder where pcap files are present,
# (b) Classification. For generating training data set pass M or NM . For generating testing data set that needs classification pass "" empty string. 
# (c) an out file into which all the extracted information in tab separated columns is writtem.    

#fd = PcapFileDataProcessor("/home/sakella/examples/structuredbayes/traffic/i-01")
#p = PcapProcessor("/home/sakella/examples/pcaps_good","B", fd)
#p.ExtractFromPcap()

