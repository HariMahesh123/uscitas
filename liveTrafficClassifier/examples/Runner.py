
from PcapFileDataExtract import PcapFileDataProcessor, PcapStreamDataProcessor, PcapProcessor
import Sniffer
import sys, getopt

def extract_malware_train_data(inputfolder, outputfile):
    fd = PcapFileDataProcessor(outputfile)
    p = PcapProcessor(inputfolder, "M", fd)
    p.ExtractFromPcap()

# first extract malware data and write it to a file.
def extract_benign_train_data(inputfolder, outputfile):
    fd = PcapFileDataProcessor(outputfile)
    p = PcapProcessor(inputfolder,"B", fd)
    p.ExtractFromPcap()
    
def run(inputfolder):
    strm = PcapStreamDataProcessor(inputfolder, "attr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tattr\tclass")
    ext = PcapProcessor("","", strm)
    s = Sniffer.Sniffer( False, -1, "tcp", ext)
    s.ReadPackets()
    
def main(argv):
    inputfolder = ''
    outputfile = ''
    optflag = ''
    print argv
    try:
        opts, args = getopt.getopt(argv,"hmbci:o:",["ifile=","ofile="])
    except getopt.GetoptError:
        print 'runner.py -h'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print "To generate training data using malware pcaps:"
            print 'runner.py -t -m -i <path to folder containing pcaps> -o <path and outputfile filename for extracted data>'
            print "To generate training data using good pcaps:"
            print 'runner.py -t -b -i <path to folder containing pcaps> -o <path and outputfile filename for extracted data>'
            print "To sniff and classify URLs being browsed:"
            print 'sudo runner.py -c <path to folder containing training data>'
            sys.exit()
        elif opt == '-m':
            optflag = 'M'
        elif  opt == '-b':
            optflag = 'B'
        elif  opt == '-c':
            optflag = 'C'
        elif opt in ("-i", "--ifile"):
            inputfolder = arg
        elif opt in ("-o", "--ofile"):
            outputfile = arg

   
    if optflag == 'M':
        print 'Generate Malware training data. Input folder is ', inputfolder , 'Output file is ', outputfile
        extract_malware_train_data(inputfolder, outputfile);
        sys.exit()
    
    if optflag == 'B':
        print 'Generate Benign training data. Input folder is ', inputfolder , 'Output file is "', outputfile
        extract_benign_train_data(inputfolder, outputfile);
        sys.exit()
        
    if optflag == 'C':
        print 'Classify URLS live ', inputfolder 
        run(inputfolder);
        sys.exit()
    

if __name__ == "__main__":
    main(sys.argv[1:])


