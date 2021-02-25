
import pcapy

class Sniffer:
    CONST_BUFSIZ =  65536
    LOOP_INFINITE = -1
    def __init__(self, mode, timeout, pcapFilter, dataProcessor):
        device = self.ListDevices()
        print "Sniffing device " + device[0]
        self.pc = pcapy.open_live(device[0], self.CONST_BUFSIZ, mode, timeout)
        self.pc.setfilter(pcapFilter)
        self.ext = dataProcessor
        
    def ListDevices(self):
        devices = pcapy.findalldevs()
        print "Available devices are :"
        for d in devices :
            print d
        return devices
    
    def HandlePkt(self, hdr, data):
        self.ext.ExtractFromBuffer(data)
             
    def ReadPackets(self, loop = LOOP_INFINITE):
        self.pc.loop(loop, self.HandlePkt)

#uncomment for unit testing
# strm = PcapStreamDataProcessor("/home/sakella/examples/structuredbayes/traffic/i", "attr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tclass")
# ext = PcapProcessor("","", strm)
# s = Sniffer( False, -1, "tcp", ext)
# s.ReadPackets()
