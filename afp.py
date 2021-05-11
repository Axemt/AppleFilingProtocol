import socket
import os
import sys, getopt
from random import randrange
import struct

# POG
#
# https://developer.apple.com/library/archive/documentation/Networking/Conceptual/AFP/Introduction/Introduction.html

#
# https://en.wikipedia.org/wiki/Data_Stream_Interface
#

#
# Possible docs from open source implementation?
# https://github.com/mabam/CAP/tree/master/lib/afp
#


session = None

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

def DSIEncapsulateCommand(function) -> bytes:
    global session
    
    def _DSIEncapsulateCommand(*args, **kwargs):
        global session

        payload = function(*args, **kwargs)
        
        # sometimes session ID is represented weirdly when printing, investigate?
        if session == None:
            session = randrange(0,65536)

        ''' 
        DSI Header Format:

        |----------32 bit---------|

        |req/rep1B|Comm 1B|Sess 2B|
        |------Offset 4B----------|
        |---Payload Len 4B--------|
        |---Reserved 4B (all 0)---|

        |-----Payload ??B------...

        '''
        stru = struct.pack("!2B H 3I", 0, 2, session, 0, len(payload), 0) + payload
                            #format string
                            # ! = network
                            # B = 1B, unsigned
                            # H = 2B, unsigned
                            # I = 4B, unsigned
        return(stru)

    return(_DSIEncapsulateCommand)

def DSIGetStatus() -> bytes:
    global session

    if session == None:
        session = randrange(0,65536)

    stru = struct.pack("!2B H 3I", 0, 3, session, 0, 0, 0)
                                    # 3 = GetStatus

    return(stru)


def DSIOpenSession() -> bytes:
    global session

    if session == None:
        session = randrange(0,65536)

    stru = struct.pack("!2B H 3I",0,4,session,0,0,0)
                                    # 4 = OpenSession

    return(stru)


@DSIEncapsulateCommand
def craft_FPGetSrvParams() -> bytes:

    '''
    FPGetSrvParams
    OP = 0x10 (16); FPGetSrvParams code
    Data = 0x00
    '''
    
    stru = struct.pack("!2B",16,0)
    return(stru)



def main(argv):
    global session
    host, port, path = getOpts(argv)
 
    print("> Connecting to AFP in host " + host)

    #s = socket.socket()
    #s.connect((host, port))
    print("> Successfully connected to "+host)

    request = DSIOpenSession()
    print("Session ID :",session,"("+ hex(session) + ")")
    print("DSIOpenSession",request)
    #s.send(request)

    #response = s.recv(4096)
    #print(response)

    request = DSIGetStatus()
    print("DSIGetStatus  ",request)
    #s.send(request)

    #response = s.recv(4096)
    #print(response)

    request = craft_FPGetSrvParams()
    print("FPGetSrvParams",request)
    #s.send(request)


main(sys.argv[1:])
