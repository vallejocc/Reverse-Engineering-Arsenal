################################################
##
## Author: Javier Vicente Vallejo
## Twitter: @vallejocc
## Web: http://www.vallejo.cc
##
################################################

import sys
import os
import pefile
import vigenere_attack
import xoradd_attack
import decryptors

########################################################################################################################################

def joinlist(a, b):
    for e in b:
        a.append(e)
    return a
    
####################################################################    

def recurfiles(p):
    l=[]
    for e in os.listdir(p):
        if os.path.isdir(p+"/"+e):
            l=joinlist(l,recurfiles(p+"/"+e))
        else:
            l.append(p+"/"+e)
    return l

####################################################################

def doExtractPE(deccontent, pos, n):
    if pos>0x100: pos-=0x100
    else: pos=0
    pe = None
    if pos+n>len(deccontent):n=len(deccontent)-pos
    for i in range(pos, pos+n-2):
        if deccontent[i]=='M' and deccontent[i+1]=='Z':
            try:
                pe = pefile.PE(data = deccontent[i:])
                pe = deccontent[i:i+pe.sections[-1].PointerToRawData+pe.sections[-1].SizeOfRawData]
                break
            except:
                pass
    return pe

####################################################################

def doWorkDecrypt(content, pos, alg, key, inc, extractpebackrange):    
    if alg.lower() != "noenc":        
        if alg.lower() == "vigenere":
            print "revealpe: doWorkDecrypt: decrypting %x %s" % (pos, alg)
            deccontent = decryptors.doWork(content, pos, len(content), alg, key, inc, "forward")
            pe = deccontent[pos:]
            return deccontent, pe
        else:
            print "revealpe: doWorkDecrypt: decrypting %x %s %x %x" % (pos, alg, key, inc)
            deccontent = decryptors.doWork(content, pos, len(content), alg, key, inc, "forward")
            deccontent = decryptors.doWork(deccontent, pos, len(content), alg, key, inc, "backward")
            pe = doExtractPE(deccontent, pos, extractpebackrange)
            return deccontent, pe
    else:
        print "revealpe: doWorkDecrypt: noenc"
        return None, None

####################################################################

def doWorkPESearch(target):
    
    global gnocheckaligned
    global gcheckunaligned
    global gcheckzeros
    global gnovigenere
    
    deccontent = None
    bfile = False
    pe = None
    
    if os.path.exists(target) and os.path.isfile(target):
        bfile = True
        f = open(target, "rb")
        content = f.read()
        f.close()
    else:
        content = target
        
    plaintxts = []        
    unalignedplaintxts = []
    
    owndir = os.path.dirname(os.path.abspath(__file__))
    f = open("%s/peplain.txt" % owndir, "rb")
    plaintxts = map(str.strip, f.readlines())
    f.close()
    f = open("%s/unalignedpeplain.txt" % owndir, "rb")
    unalignedplaintxts = map(str.strip, f.readlines())
    f.close()

    deccontent = None
    alg = None
    pos = None
    key = None
    inc = None
    
    ldeccontents = []
    lpes = []
    
    #ATTACK1: xor/add 1/4 byte with or without key inc, using wellknown pe header texts (plaintext aligned to 4 from MZ)
    if not gnocheckaligned:
        print "revealpe: doWorkPESearch: check aligned"
        for plaintxt in plaintxts:
            print "revealpe: doWorkPESearch: searching for plaintxt: %s" % plaintxt
            pos, l = xoradd_attack.doWork(content, plaintxt, benable1byte = True, benable4byte = True, benableincs = True, benablenoincs = True)
            if l and len(l):
                print "revealpe: doWorkPESearch: plaintxt found"                
                for e in l:
                    alg = e[0]
                    key = e[1]
                    inc = e[2]                    
                    deccontent, pe = doWorkDecrypt(content, pos, alg, key, inc, 0x100)
                    if pe:
                        print "revealpe: doWorkPESearch: aligned, pe found"
                        lpes.append((pe, pos, alg, key, inc))
                    if deccontent:
                        print "revealpe: doWorkPESearch: aligned, decrypted content found"
                        ldeccontents.append((deccontent, pos, alg, key, inc))
    
    #ATTACK2: xor/add 1/4 byte with or without key inc, using wellknown pe header texts (check all alignments)
    if gcheckunaligned:
        print "revealpe: doWorkPESearch: check unaligned"
        for unalignedplaintxt in unalignedplaintxts:
            print "revealpe: doWorkPESearch: searching for plaintxt: %s" % unalignedplaintxt
            pos, l = xoradd_attack.doWork(content, unalignedplaintxt, benable1byte = True, benable4byte = True, benableincs = True, benablenoincs = True)
            if l and len(l):
                print "revealpe: doWorkPESearch: plaintxt found"
                for e in l:
                    alg = e[0]
                    key = e[1]
                    inc = e[2]                    
                    deccontent, pe = doWorkDecrypt(content, pos, alg, key, inc, 0x100)
                    if pe:
                        print "revealpe: doWorkPESearch: unaligned, pe found"
                        lpes.append((pe, pos, alg, key, inc))
                    if deccontent:
                        print "revealpe: doWorkPESearch: unaligned, decrypted content found"
                        ldeccontents.append((deccontent, pos, alg, key, inc))
        
    ##ATTACK3: xor/add 1/4 byte with or without key inc, using zeros and decrypting from different alignments
    #ZEROS ATTACK DISABLED
    
    ##ATTACK4: vigenere attack
    if not gnovigenere:
        print "revealpe: doWorkPESearch: vigenere"
        key = 0
        inc = 0
        for res in vigenere_attack.doWork(content, onlyfirstPEfound = False):
            pos = res[0]
            sustTableVal = res[1]
            sustTableSet = res[2]
            print "revealpe: doWorkPESearch: pe found at %x" % pos
            alg = "vigenere"
            deccontent, pe = doWorkDecrypt(content, pos, alg, sustTableVal, sustTableSet, 0)
            if pe:
                print "revealpe: doWorkPESearch: vigenere, pe found"
                lpes.append((pe, pos, alg, key, 0))
            if deccontent:
                print "revealpe: doWorkPESearch: unaligned, decrypted content found"
                ldeccontents.append((deccontent, pos, alg, key, 0))
            key+=1
    
    if bfile:
        for e in lpes:
            pe = e[0] 
            pos = e[1] 
            alg = e[2] 
            key = e[3] 
            inc = e[4]
            f = open("%s.%s_%x_%x_%x.decpe" % (target, alg, pos, key, inc), "wb")
            f.write(pe)
            f.close()
        for e in ldeccontents:
            deccontent = e[0] 
            pos = e[1] 
            alg = e[2] 
            key = e[3] 
            inc = e[4]
            f = open("%s.%s_%x_%x_%x.dec" % (target, alg, pos, key, inc), "wb")
            f.write(deccontent)
            f.close()

    return lpes, ldeccontents

####################################################################

def doWorkRawSearch(target, plaintxt):

    global gcheckunaligned
    
    deccontent = None
    bfile = False
    
    pendingAlignments = 1
    if gcheckunaligned: pendingAlignments = 4
        
    content = target
    try:
        if os.path.exists(target) and os.path.isfile(target):        
            bfile = True
            f = open(target, "rb")
            content = f.read()
            f.close()
    except:pass        
        
    deccontent = None
    alg = None
    pos = None
    key = None
    inc = None
    pe = None
    
    ldeccontents = []
    
    while pendingAlignments:
        #ATTACK: xor/add 1/4 byte with or without key inc, using given plaintext
        print "revealpe: doWorkRawSearch: searching for plaintxt: %s" % plaintxt
        pos, l = xoradd_attack.doWork(content, plaintxt, benable1byte = True, benable4byte = True, benableincs = True, benablenoincs = True)
        if l and len(l):
            print "revealpe: doWorkRawSearch: plaintxt found"
            for e in l:
                alg = e[0]
                key = e[1]
                inc = e[2]                        
                deccontent, pe = doWorkDecrypt(content, pos, alg, key, inc, 0x100)
                if deccontent:
                    ldeccontents.append((deccontent, pos, alg, key, inc))
        if len(ldeccontents):
            break
        pendingAlignments-=1
        plaintxt = plaintxt[1:]
            
    if bfile:
        for e in ldeccontents:
            deccontent = e[0] 
            pos = e[1] 
            alg = e[2] 
            key = e[3] 
            inc = e[4]
            f = open("%s.%s_%x_%x_%x.dec" % (target, alg, pos, key, inc), "wb")
            f.write(deccontent)
            f.close()

    return ldeccontents


####################################################################

gnocheckaligned = False
gcheckunaligned = False
gcheckzeros = False
gnovigenere = False
gplaintext = None
glog = None

def doWork(sys_argv):
    
    global gnocheckaligned
    global gcheckunaligned
    global gcheckzeros
    global gnovigenere
    global gplaintext
    global glog
    flog = None
    
    if len(sys_argv)==1: sys_argv.append("--help")
    
    for i in range(0, len(sys_argv)):
        if "--help" in sys_argv[i]:
            print """
            
            This tool searchs for PE headers encrypted with simple encryption 
            algorithms usually used by packers and malware. Under some 
            circustances, the tool is able to get the decryption key an decrypt 
            the embbeded / encrypted PE file.
            
            Currently it supports some different algorithms based on xor/add/rol 
            with key-lenght =8 and =32 bits, and key-increment each round 
            (depending on the algorithm).
            
            It support an specific attack against vigenere-like encryptors. In this
            case it creates a partial sustitution table with the equivalences found 
            between plain an encrypted text, and after that, it tries to bruteforce
            different encryption algorithms and keys, trying to find a pair matching
            the partial sustitution table.In case it finds the encryptor and the keys, 
            it decrypts the full PE, else it decrypts only a partial part of the PE 
            (only the bytes with the known equivalences).
                    
            Usage 1, apply the attack on the target file:
            
                python revealpe.py <target file> <options>
            
            Usage 2, apply the attack on the files of a directory whose filename 
            contains the matching text:
                
                python revealpe.py <target directory> <matching text> <options>
                
            Options:
            
                --no-check-aligned: disable the default aligned scanning
                --check-unaligned: if the plaintext was encrypted with key-lenght=32, 
                to obtain the key, it is necesary to apply the attack on a point of
                the plain and encrypted text aligned to 32 bits from the beggining of
                the encryption. With this option the tool will check the four possible
                alignments.                
                --no-check-vigenere: by default, the tool performs an specified attack
                for vigenere-like sustitution ciphers. If you enable this option, this
                attack is not performed.
                --plaintext: by default, the tool searchs for encrypted parts of the PE 
                header, but it is possible to specify a different plaintext to be search 
                with this option (currently, with this option the vigenere attack is
                disabled).
                --log: specify a file to write results log.
                
            """
            return
    
    for i in range(0, len(sys_argv)):
        if "--no-check-aligned" in sys_argv[i]:
            gnocheckaligned = True
        if "--check-unaligned" in sys_argv[i]:
            gcheckunaligned = True
        if "--no-check-vigenere" in sys_argv[i]:
            gnovigenere = True
        if "--plaintext" in sys_argv[i] and i+1<len(sys_argv):
            gplaintext = sys_argv[i+1]
        if "--log" in sys_argv[i] and i+1<len(sys_argv):
            glog = sys_argv[i+1]
    
    if glog: 
        flog = open(glog, "w+b")
        sys.stdout = flog
    
    print "revealpe start"
    if os.path.exists(sys_argv[1]):
        if not os.path.isdir(sys_argv[1]):
            print "revealpe: Analyzing %s" % sys_argv[1]
            print "--------------------------------------------------------------------------------"
            try:
                if not gplaintext: doWorkPESearch(sys_argv[1])
                else: doWorkRawSearch(sys_argv[1], gplaintext)
            except:
                print "Exception with sample %s" % sys_argv[1]
            print "revealpe: End"
            print "--------------------------------------------------------------------------------"
        else:
            for e in recurfiles(sys_argv[1]):
                if sys_argv[2] in e:                
                    print "revealpe: Analyzing %s" % e
                    print "--------------------------------------------------------------------------------"
                    try:
                        if not gplaintext: doWorkPESearch(e)
                        else: doWorkRawSearch(e, gplaintext)
                    except:
                        print "Exception with sample %s" % e
                    print "revealpe: End"
                    print "--------------------------------------------------------------------------------"
                    if glog: flog.flush() 
    else:
        print "revealpe: File not found"
    print "revealpe end"

    if glog: flog.close()

if __name__ == "__main__":
    doWork(sys.argv)

####################################################################


