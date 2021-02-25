


class HttpFeatureExtract:
    
    def __init__(self,type, uri, header, body):
        if(type == "http_req") :
            self.ExtractReqHeaderFeatures(header)
            self.ExtractReqURIFeatures(uri)
            self.ExtractReqBodyFeatures(body)
        else :
            self.ExtractRespHeaderFeatures(header)
            self.ExtractRespBodyFeatures(header)
        
    def ExtractReqHeaderFeatures(self, header):
        #Use HTTPAnalyzer to analyze each header that is possible under RFC.
        # A feature not being present isn't an anomaly but should raise a neutral probability so we say its NA
        # Check for custom headers. other than those specified in RFC. P
        # check each header if it contains a binary, Does it have unexpected values
        # Check cookie and extract feature from it.
        # Do an entropy calculation for the whole header set 
        print "Extracted Header"
           
    def ExtractReqURIFeatures(self, uri, header):
        # Use HTTPAnalyzer to analyze the URL for the following features below.
        # for URI possible actions are, see if the URI has a URL, tailmatch it with host.
        # perform an entropy calculation on the URI
        # check if URI is overly long and see if it binary
        # check if query exists (something after ? and see if we can get any features on this)  
        print "Extracted URI"
    
    def ExtractReqBodyFeatures(self, body, header):
        # Use HTTPAnalyzer to analyze the URL for the following features below.
        # check if content length and body match.
        # Check if body should legally exist if Get its not usually normal to have body.
        # Do an entropy calculation on the body data.
        # check if the data is binary 
        print "Extracted Body"
        
    def ExtractRespHeaderFeatures(self, header) :
        print "Extracted Response Header"
        
    def ExtractRespBodyFeatures(self, body, header) :
        print "Extracted Response Body"                        