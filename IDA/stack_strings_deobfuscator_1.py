################################################
##
## Author: Javier Vicente Vallejo
## Twitter: @vallejocc
## Web: http://www.vallejo.cc
##
################################################
## 
## Some malware families construct strings into the stack, like this:
## 
##             mov     dword ptr [ebp-18h], 61737376h ; vssa
##             mov     dword ptr [ebp-14h], 642E6970h ; pi.d
##             mov     word ptr [ebp-10h], 6C6Ch; ll
## 
## In addition, i have found malware families permutating code (they split the code in portions and the mix these portions, 
## adding jumps from a portion to the next one for getting the code being executed in the correct order), and constructing
## strings in stack, for example:
## 
##             loc_4751A4:
##               nop
##               mov     dword ptr [ebp-18h], 61737376h ; vssa
##               nop
##               jmp     loc_474E10                            
##                 |
##                 v                        
##             loc_474E10:
##               nop
##               mov     dword ptr [ebp-14h], 642E6970h ; pi.d
##               nop
##               jmp     loc_475532            
##                 |
##                 v            
##             loc_475532:
##               mov     word ptr [ebp-10h], 6C6Ch; ll
##               jmp     loc_4750C3
## 
## This script add coments at points of code where each part of the string is being reconstructed. In addition it tries to
## construct for each function the string being constructed into the function. For this purpose, it needs to follow basic
## blocks of each funcion in the same order that they are going to be executed (in this way the strings will be reconstructed
## in the same order in spite of the fact the code is permutated). When it constructs an string, the output is like this:
## 
##    "Function text constructed in stack: sub_474CA0 |     vssapi.dllCreateVssBackupComponentsInternaVssFreeSnapshotPropertiesInternaupComponents@@@Zonents@@YGJPAPAVIVssBackreeSnapshotPropertiessBackupCompateVVssF?Cre"
##
################################################

import idaapi
import idc
import idautils

loutput = []

for segea in Segments():    

    for funcea in Functions(SegStart(segea), SegEnd(segea)):        
        
        functxt = ""
        
        functionName = GetFunctionName(funcea)
        
        #print "Current function: %s" % functionName
        
        f = idaapi.get_func(funcea)
        fc = idaapi.FlowChart(f)
        lblocks = []
        
        for block in fc:            
            lblocks.append(block)
        
        lorderedblocks = []
        
        while len(lblocks):
            first = lblocks.pop(0)
            lorderedblocks.append(first)                        
            for head in Heads(first.startEA, first.endEA):
                ins = GetMnem(head)
                if len(ins) and ins[0]=='j':
                    op0 = GetOpType(head, 0)
                    if op0==5 or op0==6 or op0==7:
                        v = GetOperandValue(head, 0)
                        for i in range(0, len(lblocks)):
                            if v == lblocks[i].startEA: 
                                #print "Moving block %x:%x" % (head, v)
                                lblocks.insert(0, lblocks.pop(i))
                                break
                                        
        for block in lorderedblocks:
            for head in Heads(block.startEA, block.endEA):     
                dism = GetDisasm(head)
                if "mov     [ebp" in dism or "mov     dword ptr [ebp" in dism or "mov     word ptr [ebp" in dism:
                    op1 = GetOpType(head, 1)
                    if op1==5 or op1==6 or op1==7:                        
                        v = GetOperandValue(head, 1)
                        curtxt = None
                        if ("mov     [ebp" in dism or "mov     dword ptr [ebp" in dism) and v>0xffffff:
                            curtxt = chr(v&0xff) + chr((v&0xff00)>>8) + chr((v&0xff0000)>>16) + chr((v&0xff000000)>>24)
                        if ("mov     word ptr [ebp" in dism) and v>0xff:
                            curtxt = chr(v&0xff) + chr((v&0xff00)>>8)
                        if curtxt:                            
                            print hex(head), ":", GetDisasm(head), "--->", curtxt
                            MakeRptCmt(head, curtxt)
                            functxt += curtxt
                            
        if len(functxt):
            loutput.append("Function text constructed in stack: " + functionName + " |     " + functxt)

for e in loutput:
    print e

                    
            
                        