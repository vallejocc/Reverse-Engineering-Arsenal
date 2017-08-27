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
import time

####################################################################
####################################################################
####################################################################   

class XorAddAttacks:
    
    ################################################################

    def __init__(self):
        self.xor1enabled = True
        self.xor4enabled = True
        self.add1enabled = True
        self.add4enabled = True
        self.incsenabled = True
        self.noincsenabled = True
        
    ################################################################
        
    def xor(self, a, b):
        sout = ""
        for i in range(0, len(a)):
            sout += (chr(ord(a[i])^ord(b[i])))
        return sout
    
    def sub(self, a, b):
        sout = ""
        for i in range(0, len(a)):
            sout += (chr((ord(b[i])-ord(a[i]))&0xff))
        return sout
            
    def calcincs(self, a):        
        sout = ""
        for i in range(0, len(a)-1):
            sout += chr((ord(a[i+1])-ord(a[i]))&0xff)
        return sout

    def issameval(self, a):
        c = a[0]
        for e in a:
            if e!=c:
                return None
        return c

    def xor4(self, a, b):
        lout = []
        for i in range(0, len(a)/4):
            va = struct.unpack("=L", a[i*4:(i*4)+4])[0]
            vb = struct.unpack("=L", b[i*4:(i*4)+4])[0]
            vxor = va^vb
            lout.append(vxor)
        return lout
    
    def sub4(self, a, b):
        lout = []
        for i in range(0, len(a)/4):
            va = struct.unpack("=L", a[i*4:(i*4)+4])[0]
            vb = struct.unpack("=L", b[i*4:(i*4)+4])[0]
            vsub = (vb-va)&0xffffffff
            lout.append(vsub)
        return lout
            
    def calcincs4(self, l):
        lout = []
        for i in range(0, len(l)-1):
            lout.append((l[i+1]-l[i])&0xffffffff)
        return lout

    def issameval4(self, l):
        c = l[0]
        for e in l:
            if e!=c:
                return None
        return c

    ################################################################

    def GenericAttackFixedPos(self, crypttxt, plaintxt):

        results = []
        
        if len(crypttxt)>=12 and len(plaintxt)>=12 and crypttxt != plaintxt:

            xored = self.xor(plaintxt, crypttxt)
            subed = self.sub(plaintxt, crypttxt)
            
            xoredincs = self.calcincs(xored)
            subedincs = self.calcincs(subed)
            
            xoredsameval = self.issameval(xored)
            subedsameval = self.issameval(subed)
            
            xoredincsameval = self.issameval(xoredincs)
            subedincsameval = self.issameval(subedincs)

            xored4 = self.xor4(plaintxt, crypttxt)
            subed4 = self.sub4(plaintxt, crypttxt)
            
            xoredincs4 = self.calcincs4(xored4)
            subedincs4 = self.calcincs4(subed4)
            
            xoredsameval4 = self.issameval4(xored4)
            subedsameval4 = self.issameval4(subed4)
            
            xoredincsameval4 = self.issameval4(xoredincs4)
            subedincsameval4 = self.issameval4(subedincs4)
            
            if self.xor1enabled and self.noincsenabled and xoredsameval!=None:
                key = ord(xoredsameval)
                inc = 0
                alg = "XOR1"
                results.append((alg, key, inc))

            if self.add1enabled and self.noincsenabled and subedsameval!=None:
                key = (-ord(subedsameval))&0xff
                inc = 0
                alg = "ADD1"
                results.append((alg, key, inc))

            if self.xor1enabled and self.incsenabled and xoredincsameval!=None:
                key = ord(xored[0])
                inc = ord(xoredincsameval)
                alg = "XOR1"
                results.append((alg, key, inc))

            if self.add1enabled and self.incsenabled and subedincsameval!=None:
                key = (-ord(subed[0]))&0xff
                inc = (-ord(subedincsameval))&0xff
                alg = "ADD1"
                results.append((alg, key, inc))
            
            if self.xor4enabled and self.noincsenabled and xoredsameval4!=None:
                key = xoredsameval4
                inc = 0
                alg = "XOR4"
                results.append((alg, key, inc))

            if self.add4enabled and self.noincsenabled and subedsameval4!=None:
                key = (-subedsameval4)&0xffffffff
                inc = 0
                alg = "ADD4"
                results.append((alg, key, inc))

            if self.xor4enabled and self.incsenabled and xoredincsameval4!=None:
                key = xored4[0]
                inc = xoredincsameval4
                alg = "XOR4"
                results.append((alg, key, inc))
                                
            if self.add4enabled and self.incsenabled and subedincsameval4!=None:                
                key = (-subed4[0])&0xffffffff
                inc = (-subedincsameval4)&0xffffffff
                alg = "ADD4"
                results.append((alg, key, inc))
           
        return results

    ################################################################
            
    def GenericAttack(self, crypttxt, plaintxt):
        
        if len(plaintxt)>=12:
        
            print "xoradd_attack: len crypttxt %x" % len(crypttxt)
            print "xoradd_attack: len plaintxt %x plaintxt %s" % (len(plaintxt), repr(plaintxt))
            
            shortplaintxt = plaintxt[0:12]
            
            for i in range(0, len(crypttxt)-len(plaintxt)):                
                #optimization: firstly, try with the shorter plaintxt necessary
                l = self.GenericAttackFixedPos(crypttxt[i:i+len(shortplaintxt)], shortplaintxt)
                if len(l):
                    #optimization: secondly, if the shorter plaintxt matched, try the full plaintxt
                    l = self.GenericAttackFixedPos(crypttxt[i:i+len(plaintxt)], plaintxt)
                    if len(l):
                        return i, l
                            
        return None, None
                
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

def doWork(target, plaintxt, benable1byte = True, benable4byte = True, benableincs = True, benablenoincs = True):

    while len(plaintxt)%4: plaintxt=plaintxt[0:-1]

    content = target
    try:
        if os.path.exists(target) and os.path.isfile(target):
            f = open(target, "rb")
            content = f.read()
            f.close()
    except:pass
        
    xa = XorAddAttacks()
    xa.xor1enabled = benable1byte
    xa.xor4enabled = benable4byte
    xa.add1enabled = benable1byte
    xa.add4enabled = benable4byte
    xa.incsenabled = benableincs
    xa.noincsenabled = benablenoincs
    pos, l = xa.GenericAttack(content, plaintxt)
    if pos != None:
        for e in l:
            alg = e[0]
            key = e[1]
            inc = e[2]
            print "xoradd_attack: Encrypted plaintext found at pos %x algorithm %s key %x inc %x" % (pos, alg, key, inc)
    else:
        print "xoradd_attack: Encrypted plaintext not found"
    return pos, l

####################################################################

if __name__ == "__main__":
    plaintxt = sys.argv[1]
    if os.path.exists(plaintxt) and os.path.isfile(plaintxt):
        f = open(plaintxt, "rb")
        plaintxt = f.read()
        f.close()
    if not os.path.isdir(sys.argv[2]):
        doWork(sys.argv[2], plaintxt)
    else:
        for e in recurfiles(sys.argv[2]):
            if sys.argv[3] in e:
                print "xoradd_attack: Analyzing %s..." % e
                print "--------------------"
                doWork(e, plaintxt)
                print "xoradd_attack: End"
                print "--------------------"

####################################################################
