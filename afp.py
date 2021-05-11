import socket
import os
import sys, getopt
import requests
from random import randrange
import struct

session = None

def getOpts(argv):
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

def DSTEncapsulate(function):
    global session
    
    def _DSTEncapsulate(*args, **kwargs):
        global session

        payload = function(*args, **kwargs)
        
        # sometimes session ID is represented weirdly when printing, investigate?
        if session == None:
            session = randrange(0,65535)

        stru = struct.pack("!2B H 3I", 0, 2, session, 0, len(payload), 0) + payload
                            #format string
                            # ! = network
                            # B = 1B, unsigned
                            # H = 2B, unsigned
                            # I = 4B, unsigned
        ''' 
        DST Header Format:

        |----------32 bit---------|

        |-OP 1B-|Comm 1B|-Sess 2B-|
        |------Offset 4B----------|
        |---Payload Len 4B--------|
        |---Reserved 4B (all 0)---|
        |-----Payload ??B------...

        '''

        return(stru)

    return(_DSTEncapsulate)


@DSTEncapsulate
def craft_FPGetSrvParams():

    stru = struct.pack("!2B",16,0)
    
    '''
    FPGetSrvParams
    OP = 0x10 (16); FPGetSrvParams code
    Data = 0x00
    '''

    return(stru)



def main(argv):
    global session
    host, port, path = getOpts(argv)

    s = socket.socket()
 
    print("> Connecting to AFP in host " + host)
    s = socket.socket()
    s.connect((host, port))
    print("> Successfully connected to "+host)
    request = craft_FPGetSrvParams()

    print("Session : " + session)

    print(request)

    s.send(request)
    s.close()
    response = s.recv(4096)
    print(response)



main(sys.argv[1:])
