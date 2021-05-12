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
    
    formatS = "!2b H 3I" + str(payloadLen)+"s"
    (_,_,_,resultCode,ReplySize,_,payload) = struct.unpack(formatS,stru)

    '''
    resultCodes:

    0: Success
    -5001: loginCont, used to signal continuation of the login messages in DHX2

    '''

    if not resultCode in [0,-5001] :
        print("\nWARNING: Reply with error code: " + str(resultCode)+"\n")
    return(payload)
    
def getSessionID():
    global session
    return session

def DSIGetStatus() -> bytes:
    global session

    if session == None:
        session = randrange(0,65536)

    stru = struct.pack("!2B H 3I", 0, 3, session, 0, 0, 0)
                                    # 3 = GetStatus

    return(stru)


def parse_DSIGetStatusReply(struc: bytes):
    
    print("\n------------GetStatus----------")

    machineOffset = int.from_bytes(struc[:2],"big")
    machineNameL = struc[machineOffset]
    machineName = codecs.decode(struc[machineOffset+1: machineOffset+machineNameL+1],"UTF-8")
    
    print("Machine Name:",machineName)

    flags = struc[8:10]
    print("Flags:",flags,"\n")

    UAMOffset = int.from_bytes(struc[4:6],"big")
    UAMEnd = SignatureOffset = int.from_bytes(struc[machineOffset-10: machineOffset-8],"big")
    UAM = struc[UAMOffset:UAMEnd]
    print("User Auth Modules:\n",UAM)
    # I have absolutely no clue why but if it is printed as string with decode and there's no \n they "merge"
    # Also one of the UAM gets cut from the string if using decode???

    SignatureEnd = int.from_bytes(struc[machineOffset-8: machineOffset-6],"big")
    ServerSig = struc[SignatureOffset:SignatureEnd+1]
    print("Server Signature:\n",ServerSig)
    
    AFPSupportedNumb = struc[machineOffset+machineNameL+1]
    AFPSupportedLen = AFPSupportedNumb * 6+AFPSupportedNumb
    AFPSupportedProt = codecs.decode(struc[machineOffset+machineNameL:machineOffset+machineNameL+AFPSupportedLen+2],"ascii")
    print("Supported AFP Versions: \n" + AFPSupportedProt)


    print("-------------------------------\n")
    

def DSIOpenSession() -> bytes:
    global session

    if session == None:
        session = randrange(0,65536)

    stru = struct.pack("!2B H 3I",0,4,session,0,0,0)
                                    # 4 = OpenSession

    return(stru)


def parse_DSIOpenSessionReply(struc: bytes):

    ind = 0
    lenIndex = 1
    print("\n----------OpenSession----------")

    while(ind < len(struc) and struc[ind] != None):
        opt = struc[ind]
        optLen = struc[lenIndex]
        optVal = int.from_bytes(struc[lenIndex+1:lenIndex+optLen+1],"big")
        print("Option:",opt,"Option Value:", optVal)

        ind = lenIndex + optLen +1
        lenIndex = lenIndex + optLen+2
    
    print("-------------------------------\n")


def DSICloseSession() -> bytes:
    global session

    # Session must exist to close it lol
    if session == None:
        raise RuntimeError("Cannot close non-existent session")

    stru = struct.pack("!2B H 3I",0,1,session,0,0,0)

    return(stru)


@DSIEncapsulateCommand
def craft_FPGetSrvrParams() -> bytes:

    '''
    FPGetSrvrParams
    Auth (if present) required

    OP = 0x10 (16); FPGetSrvrParams code
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
    # Using DHX2 (Diffie-Helman key eXchange 2) atm
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

def parse_FPLoginReply_DHX2(struc: bytes):
    '''
    FPLoginReply: DHX2 version
    ID = 2B, "session" for login
    g = 4B # signed or unsigned? :thinking
    len = 2B, length of p, Ma, Mb
    p = pLenB, Sophie-Germain Prime Number. 512B at minimum #possible problem using pascal strings and size??
    Mb = pLenB, g^Rb mod p. Sent by server. Same length than p. Null padded at MSB end

    ResultCode = ??B, ??plen

    '''
    print("RAW\n",struc)

    pLength = int.to_bytes(struc[6:8],"big")
    resultCode = int.to_bytes(struc[8+pLength*2:],"big")
    struc = struc[:8+pLength*2+1]

    # s is the only variable length format, store p and Mb there and convert
    formatS = "!H I H H " + str(pLength) + "s" + str(pLength) + "s"

    (ID,g,_,_,p,Mb) = struct.unpack(formatS,struc)

    # convert p and Mb to int
    p = int.to_bytes(bytes(p),"big")
    Mb = int.to_bytes(bytes(Mb),"big")

    print("---------FPLoginReply----------\n")
    print("\nResult Code:",resultCode,"\n")
    print("ID:",id)
    print("g:",g)
    print("len:",pLength)
    print("p:\n\tlength:",len(p),"\n\tp:",p)
    print("Mb:\ntlength;",len(Mb),"\n\tMb:",Mb)
    print("-------------------------------\n")
    return(ID,g,pLength,p,Mb)

