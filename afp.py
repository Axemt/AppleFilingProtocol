import socket
import os
import sys, getopt

import afpLib as afp

def getOpts(argv):
    host = port = path = None
    try:
        opts, args = getopt.getopt(sys.argv[1:], "h:p:f", ["host=","port=","Path="])
    except getopt.GetoptError as err:
        print(str(err)) 
        print("Usage: ComparePlot.py  [-h Destination IP] [-p Port of the machine]  [-f File/Folder path to copy]")
        sys.exit(2)
    for o, a in opts:
        if o in ("-h", "--host"):
            host = a
        elif o in ("-p","--port"):
            port = int(a)
        elif o in ("-f", "--fpath"):
            path = a
        else:
            assert False, "unhandled option"

    if None in [host,port,path]:
        raise SyntaxError("Invalid argument formats")        

    return  (host, port, path)


def main(argv):
    global session
    host, port, path = getOpts(argv)
 
    print("> Connecting to AFP in host " + host+"...")

    s = socket.socket()
    s.connect((host, port))
    print("> Successfully connected to "+host+"\n")

    DSIGetStatusRequest = afp.DSIGetStatus()
    #print("DSIGetStatus            ",DSIGetStatusRequest)
    s.send(DSIGetStatusRequest)

    Reply = s.recv(4096)
    DSIGetStatusReply = afp.DSIDisencapsulateReply(Reply)
    #print("DSIGetStatus: Reply     ",DSIGetStatusReply)
    afp.parse_DSIGetStatusReply(DSIGetStatusReply)
    
    s.close()

    # The "real world" captures we're reversing change host port number after a successful GetStatus, interesting
    # see Research Captures/sample_successful_connect.pcapng

    s = socket.socket()
    s.connect((host,port))

    DSIOpenSessionRequest = afp.DSIOpenSession()
    print("Session ID :",afp.getSessionID(),"("+ hex(afp.getSessionID()) + ")")
    #print("DSIOpenSession          ",DSIOpenSessionRequest)
    s.send(DSIOpenSessionRequest)

    Reply = s.recv(4096)
    DSIOpenSessionReply = afp.DSIDisencapsulateReply(Reply)
    afp.parse_DSIOpenSessionReply(DSIOpenSessionReply)

    print("DSIOpenSession: Reply   ",DSIOpenSessionReply)
 

    FPLoginRequest = afp.craft_FPLoginRequest("abc")
    print("FPLoginRequest          ",FPLoginRequest)
    s.send(FPLoginRequest)

    FPLoginReply = s.recv(4096)
    #print("FPLoginReply            ",FPLoginReply)
    (ID,g,leng,p,Mb) = afp.parse_FPLoginReply_DHX2(FPLoginReply)

    closeS = afp.DSICloseSession()
    print("DSICloseSession         ",closeS)
    s.send(closeS)
    s.close()


main(sys.argv[1:])
