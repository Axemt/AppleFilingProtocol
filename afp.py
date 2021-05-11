import socket
import os
import sys, getopt
from random import randrange
import struct
import codecs

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


def DSIDisencapsulateReply(stru: bytes) -> bytes:
    # we need to know the length of the payload before unpacking
    # yes I could just slice the bytes array but this allows for error checking and retrieval
    # of other parameters if they are ever useful

    payloadLen = int.from_bytes(stru[8:12],byteorder="big")
    
    formatS = "!2B H 3I" + str(payloadLen)+"s"
    (_,_,_,resultCode,ReplySize,_,payload) = struct.unpack(formatS,stru)
    if resultCode != 0:
        print("\nWARNING: Reply with error code: " + str(resultCode)+"\n")
    return(payload)
    


def parse_DSIGetStatusReply(struc: bytes):
    machineOffset = int.from_bytes(struc[:2],"big")
    machineNameL = struc[machineOffset]
    machineName = codecs.decode(struc[machineOffset+1: machineOffset+machineNameL+1],"UTF-8")
    
def parse_DSIOpenSessionReply(struc: bytes):

    ind = 0
    lenIndex = 1
    while(ind < len(struc) and struc[ind] != None):
        opt = struc[ind]
        optLen = struc[lenIndex]
        optVal = int.from_bytes(struc[lenIndex+1:lenIndex+optLen+1],"big")
        print("Option:",opt,"Option Value:", optVal)

        ind = lenIndex + optLen +1
        lenIndex = lenIndex + optLen+2

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

def DSICloseSession() -> bytes:
    global session

    # Session must exist to close it lol
    if session == None:
        raise RuntimeError("Cannot close non-existent session")

    stru = struct.pack("!2B H 3I",0,1,session,0,0,0)

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


@DSIEncapsulateCommand
def craft_FPLoginRequest(user: str) -> bytes:

    #
    # UNFINISHED 
    #
    # For login, see:
    # https://developer.apple.com/library/archive/documentation/Networking/Conceptual/AFP/AFPSecurity/AFPSecurity.html#//apple_ref/doc/uid/TP40000854-CH232-81479
    #
    #
    '''
    FPLoginRequest
    OP = 0x12 (18)
    String (AFP version) = Field Length + "AFP3.3"
    String (Auth method) = Field Length + "DHX2" # there are more, including no auth but this is what I work with atm
    String (user to log) = Field Length+ <user>
    '''

    AFPVer = bytes("AFP3.3","ascii")
    Auth = bytes("DHX2","ascii")
    user = bytes(user,"ascii")
    formatS = "!2B"+str(len(AFPVer))+"s B"+str(len(Auth))+"s B "+str(len(user))+"s"

    stru = struct.pack(formatS,18,len(AFPVer),AFPVer,len(Auth),Auth,len(user),user)

    return(stru)


def main(argv):
    global session
    host, port, path = getOpts(argv)
 
    print("> Connecting to AFP in host " + host+"...")

    s = socket.socket()
    s.connect((host, port))
    print("> Successfully connected to "+host)

    DSIOpenSessionRequest = DSIOpenSession()
    print("Session ID :",session,"("+ hex(session) + ")")
    print("DSIOpenSession          ",DSIOpenSessionRequest)
    s.send(DSIOpenSessionRequest)

    Reply = s.recv(4096)
    DSIOpenSessionReply = DSIDisencapsulateReply(Reply)
    parse_DSIOpenSessionReply(DSIOpenSessionReply)

    print("DSIOpenSession: Reply   ",DSIOpenSessionReply)

    DSIGetStatusRequest = DSIGetStatus()
    print("DSIGetStatus            ",DSIGetStatusRequest)
    s.send(DSIGetStatusRequest)

    Reply = s.recv(4096)
    DSIGetStatusReply = DSIDisencapsulateReply(Reply)
    parse_DSIGetStatusReply(DSIGetStatusReply)
    print("DSIGetStatus: Reply     ",DSIGetStatusReply)

    FPLoginRequest = craft_FPLoginRequest("abc")
    print("FPLoginRequest          ",FPLoginRequest)
    s.send(FPLoginRequest)

    FPLoginReply = s.recv(4096)
    print("FPLoginReply            ",FPLoginReply)

    closeS = DSICloseSession()
    print("DSICloseSession         ",closeS)
    s.send(closeS)
    s.close()


main(sys.argv[1:])
