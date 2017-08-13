
$>a<dump_injected_pe_rwemem.wdbg <destination directory>
--------------------------------------------------------

This windbg script will walk the results of !address command for each process in the debuggee machine, 
searching for RWE memory containing PE files (based on the analysis of PE header). 
 
When a PE file in RWE memory is found, the script will dump it. In addition to dump it, it will fix 
some fields of PE header: imagebase will be set to the address where the PE is loaded, and 
section[i].PointerToRawData = section[i].VirtualAddress (because we are dumping a mapped PE to disk and,
if we want to analyze the dumped PE with a disassembler for example, we need to fix the sections).

$$>a<anti_antidebug_rdtsc.wdbg
------------------------------

This script works in similar way than anti-rdtsc tools that install a driver.
  
The script enables flag 2 of cr4: TSD Time Stamp Disable. In this way rdtsc is a privileged instruction. 
After that, it enables the option  for stopping when user mode exception (gflag +sue +soe, gflags 0x20000001).
Then we enable 0xc0000096 -> privileged instruction.    
In this way, when rdtsc is executed by an application, an exception will occur and windbg will catch the exception.
In that moment, the script checks the ins code of rdtsc, 0x310f. If it is a rdtsc instruction, it skips 
the instruction ip = ip+2.
Finally it sets edx = 0, and eax = last_counter+1.
Applications execution rdtsc will see an increment of 1 each rdtsc execution.

$$>a<change_object_name.wdbg <full object path + name>                                                                                              
------------------------------------------------------

i.e. pafish tries to open vmware devices "\\\\.\\HGFS" and "\\\\.\\vmci", 
if can use this script to rename these devices in this way:           
                                                                                                                                                   
change_object_name.wdbg \\global??\\hgfs  (in this case we rename the symboliclink)   \\global??\\hgfs -> \\global??\\agfs                  
change_object_name.wdbg \\devices\\vmci   (in this case we rename the deviceobject)   \\devices\\vmci -> \\devices\\amci                    
                                                                                                                                                    
The script changes the first letter of the name (setting 'a'). 
If you need other letter or additional modifications, it is easy to modify the script.

$$>a<change_process_name.wdbg <main module of the process to be renamed>
------------------------------------------------------------------------

i.e. if we want to rename vmtoolsd.exe:

$$>a<change_process_name.wdbg vmtoolsd.exe   ->  it will rename the process to vmtoolse

The script increase +1 the last letter of the name. If you need other or additional modifications, 
it is easy to modify the script.
  
$$>a<dump_process_symbols_to_file.wdbg <path> <proc>                                                                                                 
----------------------------------------------------  
  
This simple script will dump to a file all the symbols of the given process.                                                                         
If you dump a PE from memory, it could have variables pointing to symbols (for example, api 
addresses that it got with GetProcAddress, etc...).      
It is useful to have a list of pairs (symbol, address) because in this way if we open the 
dumped PE with IDA we can search for that addresses and set a name for the variable containing them.                                                                                                     

$$>a<load_code_to_kernel_memory.wdbg <src code> <mem size> <offset start routine>
---------------------------------------------------------------------------------

Allocates kernel memory and load a block of data to that kernel memory. Later it creates a kernel thread
starting to run on the given offset.

$$>a<log_processes.wdbg <destination directory>
-----------------------------------------------

Log running processes to a given file.

$$>a<pagein_range.wdbg <start_address> <end_address> <process>
--------------------------------------------------------------

Page into memory a range of memory of the given process.

$$>a<search_bytes_all_processes.wdbg <byte1> <byte2> ... <byteN>       (max 16 bytes)
-------------------------------------------------------------------------------------

This script is useful for search a max of 16 given bytes through all the running processes.

$$>a<search_string_target_process.wdbg <proc> <byte1> <byte2> .. <byteN>
------------------------------------------------------------------------

This script is useful for search a max of 16 given bytes in the given process.

$$>a<search_string_all_processes.wdbg <string>
----------------------------------------------

This script is useful for search a given string through all the running processes.
  
$$>a<search_string_target_process.wdbg <proc> <string> 
-----------------------------------------------------

This script is useful for search a given string in a given process.

$$>a<secure_writemem.wdbg <start> <end> <process> <targetdir> <ext>
-------------------------------------------------------------------

this script tries to dump a range of memory. 
If its not possible to dump a part of the range, that part if filled with random data
(really its filled with "\x11\x11\x11......\x11\x20\x0d\x0a" (total length 0x1000 for each page filled), 
but we must not assume it will always contain this value.

$$>a<show_address_info.wdbg <address> <process>
-----------------------------------------------

Show info about a given address of a given process.

$$>a<show_proc_from_handle.wdbg <handle>
----------------------------------------

Show a process info from a given handle.

$$>a<symbols.wdbg
-----------------

Load symbols.


