################################################
##
## Author: Javier Vicente Vallejo
## Twitter: @vallejocc
## Web: http://www.vallejo.cc
##
################################################

import sys
import os
import struct

####################################################################
####################################################################
####################################################################   

class Decryptors:

    ################################################################

    def __init__(self):
        pass

    ################################################################
    
    def xor1forward(self, buf, key, inc):
        bufout = ""
        for i in range(0, len(buf)):
            bufout += chr(ord(buf[i])^key)
            key += inc
            key &= 0xff
        return bufout
    
    def xor1backward(self, buf, key, inc):
        key = (key-(inc*len(buf)))&0xff
        return self.xor1forward(buf, key, inc)

    def xor4forward(self, buf, key, inc):
        bufout = ""
        for i in range(0,len(buf)/4):
            v = struct.unpack("=L", buf[i*4:(i*4)+4])[0]
            v ^= key
            bufout += struct.pack("=L", v)
            key += inc
            key &= 0xffffffff
        return bufout
    
    def xor4backward(self, buf, key, inc):
        buf = buf[len(buf)%4:]
        key = (key - ((len(buf)/4)*inc))&0xffffffff
        return self.xor4forward(buf, key, inc)
        
    def add1forward(self, buf, key, inc):
        bufout = ""
        for i in range(0, len(buf)):
            bufout += chr((ord(buf[i])+key)&0xff)
            key += inc
            key &= 0xff
        return bufout
    
    def add1backward(self, buf, key, inc):
        key = (key-(inc*len(buf)))&0xff
        return self.add1forward(buf, key, inc)
        
    def add4forward(self, buf, key, inc):
        bufout = ""
        for i in range(0,len(buf)/4):            
            v = struct.unpack("=L", buf[i*4:(i*4)+4])[0]            
            v += key
            v &= 0xffffffff        
            bufout += struct.pack("=L", v)
            key += inc
            key &= 0xffffffff
        return bufout
    
    def add4backward(self, buf, key, inc):
        buf = buf[len(buf)%4:]
        key = (key - ((len(buf)/4)*inc))&0xffffffff
        return self.add4forward(buf, key, inc)

    ################################################################
    
    def decryptVigenere(self, buf, sustTableVal, sustTableSet):
        bufout = ""
        for e in buf:
            if sustTableSet[ord(e)]: bufout += chr(sustTableVal[ord(e)])
            else: bufout += "\0"
        return bufout
    
    ################################################################
    
    def decrypt(self, buf, pos, n, alg, key, inc = 0, direction = "forward"):
        
        if "4" in alg:
            key = key&0xffffffff
            inc = inc&0xffffffff
        if "1" in alg:
            key = key&0xff
            inc = inc&0xff
        
        orig = buf
        
        if direction == "forward": 
            if pos+n>len(buf): n=len(buf)-pos
            buf = buf[pos:pos+n]
        else: 
            if n>pos: n=pos
            buf = buf[pos-n:pos]
        
        if alg.lower() == "vigenere":
            buf = self.decryptVigenere(buf, key, inc)
        if alg.lower() == "xor1":
            if direction.lower() == "forward":
                buf = self.xor1forward(buf, key, inc)
            else:
                buf = self.xor1backward(buf, key, inc)
        if alg.lower() == "xor4":
            if direction.lower() == "forward":
                buf = self.xor4forward(buf, key, inc)
            else:
                buf = self.xor4backward(buf, key, inc)        
        if alg.lower() == "add1":
            if direction.lower() == "forward":
                buf = self.add1forward(buf, key, inc)
            else:
                buf = self.add1backward(buf, key, inc)
        if alg.lower() == "add4":
            if direction.lower() == "forward":
                buf = self.add4forward(buf, key, inc)
            else:
                buf = self.add4backward(buf, key, inc)
        
        if direction == "forward": buf = orig[0:pos] + buf + orig[pos+n:]
        else: buf = orig[0:pos-n] + buf + orig[pos:]
        
        return buf
    
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

def doWork(target, pos, n, alg, key, inc, direction):    
    
    content = target
    try:
        if os.path.exists(target) and os.path.isfile(target):
            f = open(target, "rb")
            content = f.read()
            f.close()
    except:pass
    
    dec = Decryptors()
    return dec.decrypt(content, pos, n, alg, key, inc, direction)

####################################################################

if __name__ == "__main__":
    #decryptors.py <pos> <n> <alg> <key> <inc> <direction> <target> <ext>
    print sys.argv
    try: pos = int(sys.argv[1], 10)
    except: pos = int(sys.argv[1], 16)
    try: n = int(sys.argv[2], 10)
    except: n = int(sys.argv[2], 16)
    try: key = int(sys.argv[4], 10)
    except: key = int(sys.argv[4], 16)
    try: inc = int(sys.argv[5], 10)
    except: inc = int(sys.argv[5], 16)

    print "pos %x n %x alg %s key %x inc %x direction %s" % (pos, n, sys.argv[3], key, inc, sys.argv[6])
    
    if not os.path.isdir(sys.argv[7]):
        sout = doWork(sys.argv[7], pos, n, sys.argv[3], key, inc, sys.argv[6])
        print len(sout)
        f = open(sys.argv[7]+".dec", "wb")
        f.write(sout)
        f.close()
    else:
        for e in recurfiles(sys.argv[7]):
            if sys.argv[8] in e:
                print "decryptor: Decrypting %s..." % e
                print "--------------------"
                sout = doWork(e, pos, n, sys.argv[3], key, inc, sys.argv[6])
                f = open(e+".dec", "wb")
                f.write(sout)
                f.close()                
                print "decryptor: End"
                print "--------------------"

####################################################################
