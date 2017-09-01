
# set_symbols_for_addresses

This scripts asks you for a file containing pairs address - symbol. It walks all segments searching for DWORDs matching the addresses of the given file of pairs address - symbols, and it will name the variable containing the address with the symbol name. This script is thought to be used together with the windbg script dump_process_symbols_to_file.wdbg.

# stack_strings_deobfuscator_1

Some malware families construct strings into the stack, like this:

            mov     dword ptr [ebp-18h], 61737376h ; vssa
            mov     dword ptr [ebp-14h], 642E6970h ; pi.d
            mov     word ptr [ebp-10h], 6C6Ch; ll

In addition, i have found malware families permutating code (they split the code in portions and the mix these portions, 
adding jumps from a portion to the next one for getting the code being executed in the correct order), and constructing
strings in stack, for example:

            loc_4751A4:
              nop
              mov     dword ptr [ebp-18h], 61737376h ; vssa
              nop
              jmp     loc_474E10                            
                |
                v                        
            loc_474E10:
              nop
              mov     dword ptr [ebp-14h], 642E6970h ; pi.d
              nop
              jmp     loc_475532            
                |
                v            
            loc_475532:
              mov     word ptr [ebp-10h], 6C6Ch; ll
              jmp     loc_4750C3

This script add coments at points of code where each part of the string is being reconstructed. In addition it tries to
construct for each function the string being constructed into the function. For this purpose, it needs to follow basic
blocks of each funcion in the same order that they are going to be executed (in this way the strings will be reconstructed
in the same order in spite of the fact the code is permutated). When it constructs an string, the output is like this:

   "Function text constructed in stack: sub_474CA0 |     vssapi.dllCreateVssBackupComponentsInternaVssFreeSnapshotPropertiesInternaupComponents@@@Zonents@@YGJPAPAVIVssBackreeSnapshotPropertiessBackupCompateVVssF?Cre"

