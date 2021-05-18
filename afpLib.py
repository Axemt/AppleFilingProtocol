from random import randrange
import struct
import codecs

from hashlib import md5
from Crypto.Cipher import CAST 
# https://pycryptodome.readthedocs.io/en/latest/src/cipher/cast.html
# https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode


# POG

#
# https://developer.apple.com/library/archive/documentation/Networking/Conceptual/AFP/Introduction/Introduction.html
#

#
# https://en.wikipedia.org/wiki/Data_Stream_Interface
#


session = None
Ra = None
PUBLIC_KEY = None

C2SIV = b"LWallace"
S2CIV = b"CJalbert"


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
    
    formatS = "!2b H i 2I" + str(payloadLen)+"s"
    (_,_,_,resultCode,ReplySize,_,payload) = struct.unpack(formatS,stru)

    '''
    resultCodes:

    0: Success
    -5001: loginCont, used to signal continuation of the login messages in DHX2
    -5023: User not authenticated (or user doesn't exist on server)

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

def parse_FPLoginReply_DHX2(struc: bytes) -> (int,int, int, int, int):
    '''
    FPLoginReply: DHX2 version
    ID = 2B, "session" for login
    g = 4B # signed or unsigned? :thinking
    len = 2B, length of p, Ma, Mb
    p = pLenB, Sophie-Germain Prime Number. 512B at minimum #possible problem using pascal strings and size??
    Mb = pLenB, g^Rb mod p, where Rb is a random number generated by server. Same length as p. Null padded at MSB end

    ResultCode = ??B, ??plen

    '''
    pLength = int.from_bytes(struc[6:8],"big")
    resultCode = int.from_bytes(struc[8+pLength*2:],"big")
    struc = struc[:8+pLength*2+1]

    # s is the only variable length format, store p and Mb there and convert
    formatS = "!H I H " + str(pLength) + "s" + str(pLength) + "s"

    (ID,g,_,p,Mb) = struct.unpack(formatS,struc)
         #^ this should be pLength

    # convert p and Mb to int
    p = int.from_bytes(bytes(p),"big")
    Mb = int.from_bytes(bytes(Mb),"big")

    print("---------FPLoginReply----------\n")
    print("Result Code:",resultCode)
    print("ID:",ID)
    print("g:",g)
    print("len:",pLength)
    print("p:\n\tlength:",pLength,"\n\tp:",p)
    print("Mb:\n\ttlength;",pLength,"\n\tMb:",Mb)
    print("-------------------------------\n")
    return(ID,g,pLength,p,Mb)

@DSIEncapsulateCommand
def craft_FPLoginCont_DHX2(ID,g,pLength,p,Mb) -> bytes:
    global C2SIV, Ra, PUBLIC_KEY
    '''
    FPLoginCont: DHX2 Version

    FPLoginCont OPcode = 2B, 0x13 (19)
    ID = 2B, "session" for login
    Ma = pLengthB, g^Ra mod p, where Ra is a pLength random number generated by the client. Same length as p. Null padded at MSB end
    (client nOnce, C2SIV)k = 16B, nOnce encrypted with CAST-128 CBC with init vector C2SIV
    The key for encryption is K, MD5(Mb^Ra mod p). This key coincides with the one generated at the server, MD5(Ma^Rb mod p):

    "As with DHX, in DHX2 the client and server each generate a random number, Ra and Rb respectively, which serve as “private keys” for the session."

    '''

    Ra = randrange(0,(pLength*8) ** 2)

    Ma = int.to_bytes(int(pow(g,Ra,p)),pLength,"big") 
    Ma = int.from_bytes(Ma,"big") 
    # black magic to ensure plength

    PUBLIC_KEY = md5(int.to_bytes(pow(Mb, Ra, p),pLength,"big")).digest() # Server's Public key

    #nOnce = randrange(0,16383) # (16B+8)² - 1 in case nOnce + 1 is over 16B
    nOnce = 0
    Ra = Ra.to_bytes(pLength,"big")
    print("nOnce:",nOnce)

    cypher = CAST.new(PUBLIC_KEY,CAST.MODE_CBC,iv=C2SIV)

    CASTK = cypher.encrypt(nOnce.to_bytes(16,"big"))

    #cypher = CAST.new(PUBLIC_KEY,CAST.MODE_CBC,iv=C2SIV)
    #print("CASTK test decrypt:", int.from_bytes(cypher.decrypt(CASTK),"big"))

    formatS = "!2B" + str(pLength) +"s" + str(len(CASTK)) + "s"
    stru = struct.pack(formatS,19,ID,Ma.to_bytes(pLength,"big"),CASTK)

    return(stru)

def parse_FPLoginContReply_DHX2(stru: bytes, ID):
    global PUBLIC_KEY,S2CIV
    '''
    FPLoginContReply: DHX2 Version
    ID+1 = 2B, previous sent ID+1
    (clientnOnce + 1, serverNonce, S2CIV)k = 16B encrypted nOnce sent previously, server nOnce. encrypted with K
    result code, ??B
    '''
    print("-------FPLoginContReply---------\n")

    (IDplus1,enc) = struct.unpack("!H 32s",stru)
    
    print("Sent ID:",ID,"Received ID:",IDplus1,";Match =",ID +1 == IDplus1)

    cipher = CAST.new(PUBLIC_KEY,CAST.MODE_CBC, S2CIV)

    desen = cipher.decrypt(enc)
    print("Full desen:",desen)
    desen1 = desen[:16]
    desen2 = desen[16:]
    print("Desen1,2\n",desen1,"\n",desen2,"\n\n")


    print(int.from_bytes(desen1,"big"))
    print(int.from_bytes(desen2,"big"))
    print("--------------------------------\n")