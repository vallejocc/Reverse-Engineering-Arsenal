################################################
##
## Author: Javier Vicente Vallejo
## Twitter: @vallejocc
## Web: http://www.vallejo.cc
##
################################################
#
#  This scripts asks you for a file containing pairs address - symbol.
#  
#  This script walks all segments searching for DWORDs matching the addresses of the given file of pairs address - symbols,
#  and it will name the variable containing the address with the symbol name.
#
#  This script is thought to be used together with the windbg script dump_process_symbols_to_file.wdbg.
#
################################################

import idaapi
import idc
import idautils
import tkFileDialog

################################################

def binarySearch(alist, item):
    first = 0
    last = len(alist)-1
    found = False
    retval = 0  
    while first<=last and not found:
        midpoint = (first + last)//2
        #algunos malware saltan al comienzo de la api mas algunas instrucciones, por ejemplo:
        #ADVAPI32!RegDeleteValueW:
        #77daedf1 8bff            mov     edi,edi
        #77daedf3 55              push    ebp
        #77daedf4 8bec            mov     ebp,esp
        #77daedf6 83ec0c          sub     esp,0Ch <- malware salta aqui y ejecuta el push ebp, mov ebp, esp en su codigo
        #Por eso no comparamos la direccion dada con la de la lista, sino que aceptamos q sea la de la lista o hasta 10 posiciones mas alante
        if alist[midpoint][0] <= item and item < alist[midpoint][0]+10: 
            found = True
            retval = midpoint
        else:
            if item < alist[midpoint][0]:
                last = midpoint-1
            else:
                first = midpoint+1    
    return found, retval

################################################

symbols = []

imagebase = idaapi.get_imagebase()
ea = here()
symbols_file_path = tkFileDialog.askopenfilename()

f = open(symbols_file_path, "r+b")
lines = f.readlines()
f.close()


##### Collect symbols by content and set symbols by rva

for line in lines:
    print line
    linesplit = line.split("          ")
    if len(linesplit)>0:
        symbolstr = linesplit[1].strip()
        symbolstr = symbolstr.replace(" = <no type information>", "").replace("(<no parameter info>)", "").replace("__CARRIAGE_RETURN__", "\r").replace("__NEWLINE__", "\n")
        if " byrva" in symbolstr:            
            symbolstr = symbolstr.replace(" byrva", "")
            if " comment" in symbolstr:
                symbolstr = symbolstr.replace(" comment", "")
                MakeComm(imagebase+int(linesplit[0],16), symbolstr)
            elif " rptcomment" in symbolstr:
                symbolstr = symbolstr.replace(" rptcomment", "")
                MakeRptCmt(imagebase+int(linesplit[0],16), symbolstr)
            else:
                MakeNameEx(imagebase+int(linesplit[0],16), symbolstr, 0)            
        else:
            symbol = (int(linesplit[0],16), symbolstr)
            symbols.append(symbol)

##### Set symbols by content

if len(symbols):
    
    symbols = sorted(symbols, key=lambda symbols: symbols[0])
    
    for seg_ea in Segments():
    
        for ea in range(seg_ea, SegEnd(seg_ea)):
            
            vop1 = None
            vop2 = None
            
            bIsCode = isCode(GetFlags(ea))
                    
            if bIsCode:
                op1type = idc.GetOpType(ea, 0)
                op2type = idc.GetOpType(ea, 1)
                if op1type == 5 or op1type == 6 or op1type == 7:
                    vop1 = GetOperandValue(ea,0)
                if op2type == 5 or op2type == 6 or op2type == 7:
                    vop2 = GetOperandValue(ea,1)
                           
            v = Dword(ea)
            
            isymbol = binarySearch(symbols, v)
            if vop1 and not isymbol[0]: isymbol = binarySearch(symbols, vop1)
            if vop2 and not isymbol[0]: isymbol = binarySearch(symbols, vop2)
            
            if isymbol[0]:
                
                i = isymbol[1]
                
                if bIsCode:
                    print "Is code!! %x %s\n" % (ea, symbols[i][1])
                    MakeComm(ItemHead(ea),symbols[i][1])
                else:
                    print "%x %s\n" % (ea, symbols[i][1])
                    MakeUnkn(ea,4)
                    MakeDword(ea)
                    MakeNameEx(ea,symbols[i][1],0)
                    MakeComm(ea,symbols[i][1])
                
                symbols[i] = (symbols[i][0], "_"+symbols[i][1])

################################################        


