import ctypes, struct
from keystone import *

CODE = (
    " start:                             "  #
    "   int3                            ;"  #   Breakpoint for Windbg. REMOVE ME WHEN NOT DEBUGGING!!!!
    "   mov   ebp, esp                  ;"  #
    "   add   esp, 0xfffffdf0           ;"  #   Avoid NULL bytes
    "   call  find_kernel32             ;"  #
    "   push  0x78b5b983                ;"  #   TerminateProcess hash
    "   call  find_function             ;"  #
    "   xor   ecx, ecx                  ;"  #   Null ECX
    "   push  ecx                       ;"  #   uExitCode
    "   push  0xffffffff                ;"  #   hProcess
    "   call  eax                       ;"  #   Call TerminateProcess

    "find_kernel32:                     "  # Label for locating kernel32.dll in memory
    "   xor   ecx, ecx                  ;"  # Zero out ECX (used as a pointer)
    "   mov   esi, fs:[ecx+30h]         ;"  # Load the address of the Process Environment Block (PEB) into ESI
    "   mov   esi, [esi+0Ch]            ;"  # ESI = PEB->Ldr (Loader Data structure)
    "   mov   esi, [esi+1Ch]            ;"  # ESI = PEB->Ldr.InInitOrder (linked list of loaded modules)

    "next_module:                       "  # Loop label to iterate through modules to find kernel32.dll
    "   mov   ebx, [esi+8h]             ;"  # EBX = Base address of the current module
    "   mov   edi, [esi+20h]            ;"  # EDI = Pointer to module name (UNICODE_STRING)
    "   mov   esi, [esi]                ;"  # Move to the next module in the list
    "   cmp   [edi+12*2], cx            ;"  # Check if the 12th character of the module name is null (indicates kernel32.dll in Unicode)
    "   jne   next_module               ;"  # If not, go to the next module
    "   ret                             ;"  # Return with kernel32.dll base address in EBX

    "find_function:                     "  # Function to locate a specific function's address
    "   pushad                          ;"  # Save all registers on the stack


    "   mov   eax, [ebx+0x3c]           ;"  # Offset to PE Signature of kernel32.dll
    "   mov   edi, [ebx+eax+0x78]       ;"  # RVA of Export Table Directory
    "   add   edi, ebx                  ;"  # Convert to VMA of Export Table Directory
    "   mov   ecx, [edi+0x18]           ;"  # Number of function names in export table
    "   mov   eax, [edi+0x20]           ;"  # RVA of AddressOfNames array
    "   add   eax, ebx                  ;"  # Convert to VMA of AddressOfNames array
    "   mov   [ebp-4], eax              ;"  # Store AddressOfNames in stack

    " find_function_loop:                "  #
    "   jecxz find_function_finished    ;"  #   Jump to the end if ECX is 0
    "   dec   ecx                       ;"  #   Decrement our names counter
    "   mov   eax, [ebp-4]              ;"  #   Restore AddressOfNames VMA
    "   mov   esi, [eax+ecx*4]          ;"  #   Get the RVA of the symbol name
    "   add   esi, ebx                  ;"  #   Set ESI to the VMA of the current symbol name

    " compute_hash:                      "  #
    "   xor   eax, eax                  ;"  #   NULL EAX
    "   cdq                             ;"  #   NULL EDX
    "   cld                             ;"  #   Clear direction

    " compute_hash_again:                "  #
    "   lodsb                           ;"  #   Load the next byte from esi into al
    "   test  al, al                    ;"  #   Check for NULL terminator
    "   jz    compute_hash_finished     ;"  #   If the ZF is set,we've hit the NULL term
    "   ror   edx, 0x0d                 ;"  #   Rotate edx 13 bits to the right
    "   add   edx, eax                  ;"  #   Add the new byte to the accumulator
    "   jmp   compute_hash_again        ;"  #   Next iteration
    
    " compute_hash_finished:             "  #

    " find_function_compare:             "  #
    "   cmp   edx, [esp+0x24]           ;"  #   Compare the computed hash with the requested hash
    "   jnz   find_function_loop        ;"  #   If it doesn't match go back to find_function_loop
    "   mov   edx, [edi+0x24]           ;"  #   AddressOfNameOrdinals RVA
    "   add   edx, ebx                  ;"  #   AddressOfNameOrdinals VMA
    "   mov   cx,  [edx+2*ecx]          ;"  #   Extrapolate the function's ordinal
    "   mov   edx, [edi+0x1c]           ;"  #   AddressOfFunctions RVA
    "   add   edx, ebx                  ;"  #   AddressOfFunctions VMA
    "   mov   eax, [edx+4*ecx]          ;"  #   Get the function RVA
    "   add   eax, ebx                  ;"  #   Get the function VMA
    "   mov   [esp+0x1c], eax           ;"  #   Overwrite stack version of eax from pushad
    
    "find_function_finished:            "  # End of function name search loop
    "   popad                           ;"  # Restore saved registers
    "   ret                             ;"  # Return from find_function
)

# Initialize the assembler in x86 32-bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)  # Assemble the code
print("Encoded %d instructions..." % count)

# Pack the encoded instructions into a shellcode byte array
sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)

# Allocate memory for the shellcode in the process's address space
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),          # Let OS decide address
                                          ctypes.c_int(len(shellcode)), # Allocation size
                                          ctypes.c_int(0x3000),      # MEM_COMMIT | MEM_RESERVE
                                          ctypes.c_int(0x40))        # PAGE_EXECUTE_READWRITE protection

# Create a buffer from the shellcode array
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

# Copy the shellcode into the allocated memory
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),             # Destination address
                                     buf,                           # Source buffer
                                     ctypes.c_int(len(shellcode)))  # Length of shellcode

print("Shellcode located at address %s" % hex(ptr))
input("...ENTER TO EXECUTE SHELLCODE...")  # Wait for user input before executing shellcode

# Create a new thread to start executing the shellcode
ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),           # Security attributes (default)
                                         ctypes.c_int(0),           # Stack size (default)
                                         ctypes.c_int(ptr),         # Starting address (shellcode)
                                         ctypes.c_int(0),           # Thread parameter (not used)
                                         ctypes.c_int(0),           # Creation flags (run immediately)
                                         ctypes.pointer(ctypes.c_int(0)))  # Thread ID (not used)

# Wait for the thread to finish executing
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))  # Wait indefinitely    
