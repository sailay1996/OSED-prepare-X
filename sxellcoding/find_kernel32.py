import ctypes, struct
from keystone import *

# Assembly code for shellcode
CODE = (
    " start:                             "  # Start of shellcode
    "   int3                            ;"  # Debug breakpoint for debugging with WinDbg (remove this in production)
    "   mov   ebp, esp                  ;"  # Save the current stack pointer in EBP
    "   sub   esp, 60h                  ;"  # Allocate 0x60 (96) bytes on the stack for local variables
    
    " find_kernel32:                     "  # Label for locating kernel32.dll
    "   xor   ecx, ecx                  ;"  # Zero out ECX register (ECX = 0)
    "   mov   esi,fs:[ecx+30h]          ;"  # Load address of the PEB (Process Environment Block) into ESI
    "   mov   esi,[esi+0Ch]             ;"  # ESI = PEB->Ldr (PEB Loader Data structure)
    "   mov   esi,[esi+1Ch]             ;"  # ESI = PEB->Ldr.InInitOrder (linked list of loaded modules)

    " next_module:                      "  # Loop label to find kernel32.dll module
    "   mov   ebx, [esi+8h]             ;"  # EBX = base address of the current module in the InInitOrder list
    "   mov   edi, [esi+20h]            ;"  # EDI = pointer to module name (UNICODE_STRING)
    "   mov   esi, [esi]                ;"  # ESI = pointer to the next module in InInitOrder list
    "   cmp   [edi+12*2], cx            ;"  # Check if the 12th character of the module name is null (unicode)
    "   jne   next_module               ;"  # If not, continue to the next module in the list
    "   ret                              "  # Return (found kernel32.dll)
)

# Initialize the assembler in x86 32-bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)

# Pack the encoded instructions into a shellcode byte array
sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)

# Allocate memory for the shellcode in the process's address space
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),          # Let the OS choose the address
                                          ctypes.c_int(len(shellcode)), # Size of the memory allocation
                                          ctypes.c_int(0x3000),      # Allocation type (0x3000 = MEM_COMMIT | MEM_RESERVE)
                                          ctypes.c_int(0x40))        # Memory protection (0x40 = PAGE_EXECUTE_READWRITE)

# Create a buffer from the shellcode array
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

# Copy the shellcode into the allocated memory
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),             # Destination address
                                     buf,                           # Source buffer
                                     ctypes.c_int(len(shellcode)))  # Length of the shellcode

print("Shellcode located at address %s" % hex(ptr))
input("...ENTER TO EXECUTE SHELLCODE...")  # Pause execution before launching the shellcode

# Create a new thread that starts executing the shellcode
ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),           # Security attributes (0 = default)
                                         ctypes.c_int(0),           # Stack size (0 = default)
                                         ctypes.c_int(ptr),         # Starting address (pointer to shellcode)
                                         ctypes.c_int(0),           # Thread parameter (not used here)
                                         ctypes.c_int(0),           # Creation flags (0 = run immediately)
                                         ctypes.pointer(ctypes.c_int(0)))  # Thread ID (not used)

# Wait for the thread to finish executing
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
