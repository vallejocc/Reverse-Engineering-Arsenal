################################################
##
## Author: Javier Vicente Vallejo
## Twitter: @vallejocc
## Web: http://www.vallejo.cc
##
################################################

import sys
import os

def ROR(x, n, bits = 32):
    mask = (2**n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (bits - n))
 

def ROL(x, n, bits = 32):
    return ROR(x, bits - n, bits)

####################################################################
####################################################################
####################################################################   

class UnknownVigenereEncryptedPESearcher:
    
    ################################################################
      
    def __init__(self, content):        
        
        self.content = content + ("\0"*0x500)
        self.curpos = -1
        self.curPE = -1
        self.curPEmatchingSignature = -1
        self.curSustTableVal = None
        self.curReverseSustTableVal = None
        self.curSustTableSet = None
        self.curReverseSustTableSet = None
        
        ###################################
        # STAGE1 SIGNATURES
        #
        # Firstly: we search encrypted pe headers based on the distance between bytes that should contains the same value,
        # for example in the first type of pe header 'n' is located at positions 0x5d, 0x5e, 0x67 and 0x6a from the start of the pe
        
        self.distanceSignature1 = [ #This program cannot be run in DOS mode
            [0x52, 0x5a, 0x61, 0x64, 0x68, 0x6b, 0x6f], #spaces
            [0x55, 0x5f, 0x71], # 'o'
            [0x54, 0x57, 0x65], # 'r'
            [0x5d, 0x5e, 0x67, 0x6a], # 'n'
            [0x59, 0x70] # 'm'            
        ]
        
        self.kwownPlaintextSignature1 = [
            [0x00, "MZ"], 
            #[0x0c, "\xff"], 
            [0x0e, "\0"], 
            [0x4e, "This program cannot be run in DOS mode"]
        ]
        
        self.distanceSignature2 = [ #This program must be run under Win32
            [0x54, 0x5c, 0x61, 0x64, 0x68, 0x6e], #spaces
            [0x56, 0x59, 0x65, 0x6d], # 'r'
            [0x5b, 0x5d], # 'm'
            [0x67, 0x6a, 0x71], # 'n'
            [0x5e, 0x66, 0x69] # 'u'            
        ]

        self.kwownPlaintextSignature2 = [
            [0x00, "MZ"], 
            #[0x0c, "\xff"], 
            [0x0e, "\0"], 
            [0x50, "This program must be run under Win32"]
        ]
        
        self.distanceSignatures = [
            self.distanceSignature1,
            self.distanceSignature2
        ]
    
        self.knownPlaintexts = [
            self.kwownPlaintextSignature1,
            self.kwownPlaintextSignature2
        ]        

        ###################################
        # STAGE2 SIGNATURES
        #
        # Secondly: if we have located a encrypted pe header (of which we know the plaintext equivalent), we can
        # start to gather a part of the plaintext-cyphertext equivalences. But if we want to gather more equivalences
        # we will need to search more probable encrypted plaintext (with the adventage that now, we now a part of 
        # the sustutions P -> C extracted from pe header equivalences).
        
        self.distanceSecondarySignature1 = [ #GetProcAddress
            [0x01, 0x0b], # 'e'
            [0x04, 0x0a], # 'r'
            [0x08, 0x09], # 'd'
            [0x0c, 0x0d]  # 's'
        ]

        self.kwownPlaintextSecondarySignature1 = [
            [0x00, "GetProcAddress"]
        ]
        
        self.distanceSecondarySignature2 = [ #LoadLibrary
            [0x00, 0x04], # 'L'
            [0x02, 0x08], # 'a'
            [0x07, 0x09]  # 'r'
        ]

        self.kwownPlaintextSecondarySignature2 = [
            [0x00, "LoadLibrary"]
        ]        

        self.distanceSecondarySignature3 = [ #GetLastError
            [0x02, 0x06], # 't'
            [0x08, 0x09, 0x0b], # 'r'            
        ]

        self.kwownPlaintextSecondarySignature3 = [
            [0x00, "GetLastError"]
        ]

        self.distanceSecondarySignature4 = [ #CreateToolhelp32Snapshot
            [0x02, 0x05, 0x0b], # 'e'
            [0x03, 0x12], # 'a'
            [0x04, 0x17], # 't'
            [0x07, 0x08, 0x16], # 'o'
            [0x09, 0x0c] # 'l'
        ]

        self.kwownPlaintextSecondarySignature4 = [
            [0x00, "CreateToolhelp32Snapshot"]
        ]

        self.distanceSecondarySignature5 = [ #GetCurrentThreadId
            [0x01, 0x07, 0x0d], # 'e'
            [0x05, 0x06, 0x0c], # 'r'
            [0x02, 0x09], # 't'
            [0x0f, 0x11], # 'd'
        ]

        self.kwownPlaintextSecondarySignature5 = [
            [0x00, "GetCurrentThreadId"]
        ]

        self.distanceSecondarySignature6 = [ #GetCurrentProcessId
            [0x01, 0x07, 0x0e], # 'e'
            [0x05, 0x06, 0x0b], # 'r'
            [0x02, 0x09], # 't'
            [0x0f, 0x10], # 's'
        ]

        self.kwownPlaintextSecondarySignature6 = [
            [0x00, "GetCurrentProcessId"]
        ]

        self.distanceSecondarySignature7 = [ #UnhandledExceptionFilter
            [0x01, 0x04, 0x11], # 'n'
            [0x07, 0x0c, 0x16], # 'e'
            [0x06, 0x14], # 'l'
            [0x0e, 0x15] # 't'
        ]

        self.kwownPlaintextSecondarySignature7 = [
            [0x00, "UnhandledExceptionFilter"]
        ]

        self.distanceSecondarySignature8 = [ #GetModuleHandle
            [0x01, 0x08, 0x0e], # 'e'
            [0x07, 0x0d], # 'l'
            [0x05, 0x0c] # 'd'
        ]

        self.kwownPlaintextSecondarySignature8 = [
            [0x00, "GetModuleHandle"]
        ]

        self.distanceSecondarySignature9 = [ #GetModuleFileName
            [0x01, 0x08, 0x0c, 0x10], # 'e'
            [0x07, 0x0b] # 'l'
        ]

        self.kwownPlaintextSecondarySignature9 = [
            [0x00, "GetModuleFileName"]
        ]

        self.distanceSecondarySignature10 = [ #IsDebuggerPresent
            [0x03, 0x08, 0x0c, 0x0e], # 'e'
            [0x01, 0x0d], # 's'
            [0x06, 0x07] # 'g'
        ]

        self.kwownPlaintextSecondarySignature10 = [
            [0x00, "IsDebuggerPresent"]
        ]

        self.distanceSecondarySignatures = [
            self.distanceSecondarySignature1,
            self.distanceSecondarySignature2,
            self.distanceSecondarySignature3,
            self.distanceSecondarySignature4,
            self.distanceSecondarySignature5,
            self.distanceSecondarySignature6,
            self.distanceSecondarySignature7,
            self.distanceSecondarySignature8,
            self.distanceSecondarySignature9,
            self.distanceSecondarySignature10
        ]
    
        self.knownSecondaryPlaintexts = [
            self.kwownPlaintextSecondarySignature1,
            self.kwownPlaintextSecondarySignature2,
            self.kwownPlaintextSecondarySignature3,
            self.kwownPlaintextSecondarySignature4,
            self.kwownPlaintextSecondarySignature5,
            self.kwownPlaintextSecondarySignature6,
            self.kwownPlaintextSecondarySignature7,
            self.kwownPlaintextSecondarySignature8,
            self.kwownPlaintextSecondarySignature9,
            self.kwownPlaintextSecondarySignature10
        ]        

    ################################################################
    
    def resetSustitutions(self):
        self.curSustTableVal = [0 for x in range(0x100)]
        self.curSustTableSet = [False for x in range(0x100)]
        self.curReverseSustTableVal = [0 for x in range(0x100)]
        self.curReverseSustTableSet = [False for x in range(0x100)]
    
    ################################################################
    
    def isCoherentWithPreviousGatheredSustitutions(self, knownPlaintext, pos):
        for e in knownPlaintext:
            plainoff = e[0]
            plaintxt = e[1]
            plainlen = len(e[1])
            crypttxt = self.content[pos+plainoff:pos+plainoff+plainlen]
            for i in range(0, plainlen):
                if self.curSustTableSet[ord(plaintxt[i])] == True:
                    if self.curSustTableVal[ord(plaintxt[i])] != ord(crypttxt[i]):
                        return False
        return True
            
    ################################################################
    
    def gatherSustitutions(self, knownPlaintext, pos):
        for e in knownPlaintext:
            print "vigenere_attack: Gathering sustitutions for %s / pos %x / pos from pe %x" % (repr(e[1]), pos+e[0], pos-self.curPE++e[0])
            plainoff = e[0]
            plaintxt = e[1]
            plainlen = len(e[1])
            crypttxt = self.content[pos+plainoff:pos+plainoff+plainlen]
            for i in range(0, plainlen):
                self.curSustTableVal[ord(plaintxt[i])] = ord(crypttxt[i])
                self.curReverseSustTableVal[ord(crypttxt[i])] = ord(plaintxt[i])
                self.curSustTableSet[ord(plaintxt[i])] = True
                self.curReverseSustTableSet[ord(crypttxt[i])] = True
        
    ################################################################
    
    def secondStageSustitutionsGathering(self, pos):
        while not self.isEnd(pos):
            isig = self.posMatchSignature(signatureindex = None, pos = pos, paramDistanceSignatures = self.distanceSecondarySignatures)
            if isig != None and not self.isPlaintext(knownPlaintext = self.knownSecondaryPlaintexts[isig], pos = pos):
                if self.isCoherentWithPreviousGatheredSustitutions(knownPlaintext = self.knownSecondaryPlaintexts[isig], pos = pos):              
                    print "vigenere_attack: : Coherent sustitutions found"
                    self.gatherSustitutions(knownPlaintext = self.knownSecondaryPlaintexts[isig], pos = pos)
                else:
                    #print "vigenere_attack: Not coherent sustitutions found"
                    pass
            pos += 1
        
    ################################################################
    
    def isEnd(self, pos):
        if pos >= len(self.content)-0x500:
            return True
        else:
            return False

    ################################################################
    
    def posMatchSubSignature(self, signatureindex, subsignatureindex, pos, paramDistanceSignatures):
        subsig = paramDistanceSignatures[signatureindex][subsignatureindex]
        v = self.content[pos+subsig[0]]
        for i in range(0, len(subsig)-1):
            if self.content[pos+subsig[i]]!=self.content[pos+subsig[i+1]]:
                return None
        return v    
    
    ################################################################
    
    def posMatchSignature(self, signatureindex, pos, paramDistanceSignatures):
        if signatureindex == None:
            for i in range(0, len(paramDistanceSignatures)):
                if self.posMatchSignature(signatureindex = i, pos = pos, paramDistanceSignatures = paramDistanceSignatures) != None:
                    return i
            return None
        else:
            alreadyseen = []
            match = signatureindex
            for i in range(0, len(paramDistanceSignatures[signatureindex])):
                v = self.posMatchSubSignature(signatureindex = signatureindex, subsignatureindex = i, pos = pos, paramDistanceSignatures = paramDistanceSignatures)
                if v == None or v in alreadyseen:
                    match = None
                    break
                else:
                    alreadyseen.append(v)
            return match
    
    ################################################################
    
    def isPlaintext(self, knownPlaintext, pos):
        for e in knownPlaintext:
            plainoff = e[0]
            plaintxt = e[1]
            plainlen = len(e[1])
            if self.content[pos+plainoff:pos+plainoff+plainlen]!=plaintxt:
                return False
        return True
    
    ################################################################
    
    def findNextPotentialPE(self):        
        self.curPE = -1
        self.curPEmatchingSignature = -1
        while not self.isEnd(pos = self.curpos):
            self.curpos += 1
            isig = self.posMatchSignature(signatureindex = None, pos = self.curpos, paramDistanceSignatures = self.distanceSignatures)
            if isig != None and not self.isPlaintext(knownPlaintext = self.knownPlaintexts[isig], pos = self.curpos):
                self.curPE = self.curpos
                self.curPEmatchingSignature = isig
                self.resetSustitutions()
                self.gatherSustitutions(self.knownPlaintexts[isig], pos = self.curpos)
                self.secondStageSustitutionsGathering(pos = self.curpos)
                break
        return self.curPE

    ################################################################
    
    @staticmethod
    def XOR_ADD_ROL(p0, i, j, k):
        return ROL(((p0^i)+j)&0xff, k, 8)
        
    @staticmethod
    def ADD_XOR_ROL(p0, i, j, k):
        return ROL(((p0+j)&0xff)^i, k, 8)
            
    @staticmethod
    def XOR_ROL_ADD(p0, i, j, k):
        return ((ROL(p0^i, k, 8)+j)&0xff)

    @staticmethod
    def ROL_XOR_ADD(p0, i, j, k):
        return (((ROL(p0, k, 8)^i)+j)&0xff)

    @staticmethod
    def ADD_ROL_XOR(p0, i, j, k):        
        return (ROL((p0+j)&0xff, k, 8)^i)

    @staticmethod
    def ROL_ADD_XOR(p0, i, j, k):        
        return (((ROL(p0, k, 8)+j)&0xff)^i)
    
    ################################################################
    
    @staticmethod
    def WellknownVigenereBruteforce(plaintxt, crypttxt):
        lout = []
        p0 = ord(plaintxt[0])
        c0 = ord(crypttxt[0])
        bfound=False
        for i in range(0,0x100):
            for j in range(0,0x100):
                for k in range(0,0x8):                    
                    if UnknownVigenereEncryptedPESearcher.XOR_ADD_ROL(p0, i, j, k)==c0:
                        bfound=True
                        for n in range(0,len(plaintxt)):
                            if UnknownVigenereEncryptedPESearcher.XOR_ADD_ROL(ord(plaintxt[n]), i, j, k)!=ord(crypttxt[n]):
                                bfound=False
                        if bfound: lout.append((UnknownVigenereEncryptedPESearcher.XOR_ADD_ROL, i, j, k))
                    if UnknownVigenereEncryptedPESearcher.ADD_XOR_ROL(p0, i, j, k)==c0:
                        bfound=True
                        for n in range(0,len(plaintxt)):
                            if UnknownVigenereEncryptedPESearcher.ADD_XOR_ROL(ord(plaintxt[n]), i, j, k)!=ord(crypttxt[n]):
                                bfound=False
                        if bfound: lout.append((UnknownVigenereEncryptedPESearcher.ADD_XOR_ROL, i, j, k))
                    if UnknownVigenereEncryptedPESearcher.XOR_ROL_ADD(p0, i, j, k)==c0:
                        bfound=True
                        for n in range(0,len(plaintxt)):
                            if UnknownVigenereEncryptedPESearcher.XOR_ROL_ADD(ord(plaintxt[n]), i, j, k)!=ord(crypttxt[n]):
                                bfound=False
                        if bfound: lout.append((UnknownVigenereEncryptedPESearcher.XOR_ROL_ADD, i, j, k))
                    if UnknownVigenereEncryptedPESearcher.ROL_XOR_ADD(p0, i, j, k)==c0:
                        bfound=True
                        for n in range(0,len(plaintxt)):
                            if UnknownVigenereEncryptedPESearcher.ROL_XOR_ADD(ord(plaintxt[n]), i, j, k)!=ord(crypttxt[n]):
                                bfound=False
                        if bfound: lout.append((UnknownVigenereEncryptedPESearcher.ROL_XOR_ADD, i, j, k))
                    if UnknownVigenereEncryptedPESearcher.ADD_ROL_XOR(p0, i, j, k)==c0:
                        bfound=True
                        for n in range(0,len(plaintxt)):
                            if UnknownVigenereEncryptedPESearcher.ADD_ROL_XOR(ord(plaintxt[n]), i, j, k)!=ord(crypttxt[n]):
                                bfound=False
                        if bfound: lout.append((UnknownVigenereEncryptedPESearcher.ADD_ROL_XOR, i, j, k))
                    if UnknownVigenereEncryptedPESearcher.ROL_ADD_XOR(p0, i, j, k)==c0:
                        bfound=True
                        for n in range(0,len(plaintxt)):
                            if UnknownVigenereEncryptedPESearcher.ROL_ADD_XOR(ord(plaintxt[n]), i, j, k)!=ord(crypttxt[n]):
                                bfound=False
                        if bfound: lout.append((UnknownVigenereEncryptedPESearcher.ROL_ADD_XOR, i, j, k))
        return lout
        
    ################################################################
        
    @staticmethod
    def WellknownVigenereBruteforceFromSustTable(sustTableVal, sustTableSet):
        lout=[]
        p=""
        c=""
        for i in range(0, len(sustTableVal)):
            if sustTableSet[i]:
                p+=chr(i)
                c+=chr(sustTableVal[i])
        print "WellknownVigenereBruteforceFromSustTable: %s %s" % (p, c)
        encryptors = UnknownVigenereEncryptedPESearcher.WellknownVigenereBruteforce(p, c)        
        if not len(encryptors):
            print "WellknownVigenereBruteforceFromSustTable: encryptor not found"
            return None        
        for encryptor in encryptors:
            print "WellknownVigenereBruteforceFromSustTable: encryptor found, calculating new sustitution table"
            print repr(encryptor)
            newSustTableVal = [0 for x in range(0x100)]
            newSustTableSet = [True for x in range(0x100)]
            newReverseSustTableVal = [0 for x in range(0x100)]
            newReverseSustTableSet = [True for x in range(0x100)]
            for i in range(0, 0x100):
                newSustTableVal[i] = encryptor[0](i, encryptor[1], encryptor[2], encryptor[3])
                newReverseSustTableVal[encryptor[0](i, encryptor[1], encryptor[2], encryptor[3])] = i
            lout.append((newSustTableVal, newSustTableSet, newReverseSustTableVal, newReverseSustTableSet))
        return lout
        
    ################################################################

####################################################################
####################################################################
####################################################################








########################################################################################################################################

def joinlist(a, b):
    for e in b:
        a.append(e)
    return a
    
####################################################################    

def recurfiles(p):
    l=[]
    for e in os.listdir(p):
        if os.path.isdir(p+"\\"+e):
            l=joinlist(l,recurfiles(p+"\\"+e))            
        else:
            l.append(p+"\\"+e)
    return l

####################################################################

def isTableAlreadyLogged(l, pos, tableVal, tableSet):
    for e in l:
        if e[0] == pos and e[1] == tableVal and e[2] == tableSet:
            return True
    return False
    
def doWork(target, onlyfirstPEfound = True):
    lout = []
    content = target
    try:
        if os.path.exists(target) and os.path.isfile(target):
            f = open(target, "rb")
            content = f.read()
            f.close()
    except:pass        
    vg = UnknownVigenereEncryptedPESearcher(content)
    while 1:
        vg.findNextPotentialPE()
        if  vg.curPE == -1:
            if onlyfirstPEfound:
                return (None, None, None)
            break
        print "vigenere_attack: PE at pos: %x" % vg.curPE
        print "vigenere_attack: Sust table:" 
        for i in range(0, len(vg.curSustTableVal)):
            if vg.curSustTableSet[i]:
                print "vigenere_attack: %c - %02x - %02x - %c" % (chr(i), i, vg.curSustTableVal[i], chr(vg.curSustTableVal[i]))
        print "vigenere_attack: bruteforcing wellknown algorithms"
        newTables = UnknownVigenereEncryptedPESearcher.WellknownVigenereBruteforceFromSustTable(vg.curSustTableVal, vg.curSustTableSet)
        if not newTables or not len(newTables):
            lout.append((vg.curPE, vg.curReverseSustTableVal, vg.curReverseSustTableSet))
        else:
            for newTable in newTables:
                vg.curSustTableVal = newTable[0]
                vg.curSustTableSet = newTable[1]
                vg.curReverseSustTableVal = newTable[2]
                vg.curReverseSustTableSet = newTable[3]            
                if not isTableAlreadyLogged(lout, vg.curPE, vg.curReverseSustTableVal, vg.curReverseSustTableSet):
                    lout.append((vg.curPE, vg.curReverseSustTableVal, vg.curReverseSustTableSet))            
        if onlyfirstPEfound:
            return lout            
    return lout

####################################################################

if __name__ == "__main__":
    if not os.path.isdir(sys.argv[1]):
        doWork(sys.argv[1])
    else:
        for e in recurfiles(sys.argv[1]):
            if sys.argv[2] in e:
                print "vigenere_attack: Analyzing %s..." % e
                print "vigenere_attack: --------------------"
                doWork(e)
                print "vigenere_attack: End"
                print "vigenere_attack: --------------------"

####################################################################
