# 32 Bit

## Vulnerable

#### File
```bash
➜  linux_Build git:(1_hello_world) ✗ file 32bit_InSecure_hello_world 
32bit_InSecure_hello_world: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=68bb5da9e18fcfccb773a34611d60ff2ca4b414b, for GNU/Linux 3.2.0, not stripped
```
* The Binary is a 32 bit ELF Executable compiled with Intel Architecture
* Uses LSB = Little Endinaness
* Uses the `/lib/ld-linux.so.2` to read the `.dynamic` section from the binary and loads the required library file
* Mimumum required kernel version to execute the binary is Linux 3.2.0
* Not Stripped = contains debug symbols (function names, metadata)
#### checksec
```bash
# brew install pwntools
➜  linux_Build git:(1_hello_world) ✗ pwn checksec 32bit_InSecure_hello_world
[*] '/Users/dhanesh/Desktop/ReversingForBeginners/basics/hello world/00_Hello World/linux_Build/32bit_InSecure_hello_world'
    Arch:       i386-32-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```
* No protections are available in the target binary

#### ldd
```bash
ldd binary_name
# brew install binutils
# export PATH=$PATH:`brew --prefix binutils`
➜  linux_Build git:(1_hello_world) ✗ readelf -d 32bit_InSecure_hello_world 

Dynamic section at offset 0x2138 contains 24 entries:
  Tag        Type                         Name/Value
 0x00000001 (NEEDED)                     Shared library: [libc.so.6]
 0x0000000c (INIT)                       0x8049000
 0x0000000d (FINI)                       0x80491a8
 0x00000019 (INIT_ARRAY)                 0x804b130
 0x0000001b (INIT_ARRAYSZ)               4 (bytes)
 0x0000001a (FINI_ARRAY)                 0x804b134
 0x0000001c (FINI_ARRAYSZ)               4 (bytes)
 0x6ffffef5 (GNU_HASH)                   0x80481cc
 0x00000005 (STRTAB)                     0x804823c
 0x00000006 (SYMTAB)                     0x80481ec
 0x0000000a (STRSZ)                      87 (bytes)
 0x0000000b (SYMENT)                     16 (bytes)
 0x00000015 (DEBUG)                      0x0
 0x00000003 (PLTGOT)                     0x804b224
 0x00000002 (PLTRELSZ)                   16 (bytes)
 0x00000014 (PLTREL)                     REL
 0x00000017 (JMPREL)                     0x80482d8
 0x00000011 (REL)                        0x80482d0
 0x00000012 (RELSZ)                      8 (bytes)
 0x00000013 (RELENT)                     8 (bytes)
 0x6ffffffe (VERNEED)                    0x80482a0
 0x6fffffff (VERNEEDNUM)                 1
 0x6ffffff0 (VERSYM)                     0x8048294
 0x00000000 (NULL)                       0x0
➜  linux_Build git:(1_hello_world) ✗ 

```
* `ldd` is not available on the macOS, so we use `readelf -d` to inspect the `.dynamic` section of the binary to inspect which is the required `*.so` file necessary for the operation.
* In the `NEEDED` section, we can see that the shared library `libc.so.6` is being used
```ad-note
The ELF binary is dynamically linked and uses two key shared components:

The dynamic linker /lib/ld-linux.so.2 (responsible for loading libraries).

The shared library libc.so.6 (providing the standard C runtime functionality it depends on).
```
#### readelf
```bash
# elf metadata
➜  linux_Build git:(1_hello_world) ✗ readelf -h 32bit_InSecure_hello_world
ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Intel 80386
  Version:                           0x1
  Entry point address:               0x8049050
  Start of program headers:          52 (bytes into file)
  Start of section headers:          10148 (bytes into file)
  Flags:                             0x0
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         11
  Size of section headers:           40 (bytes)
  Number of section headers:         29
  Section header string table index: 28
# library fil meta data
readelf -hs lib*.so
```
- The output of `readelf -h`, shows that this is a `32 Bit` binary from `Class: ELF32`
- Endianess used by the binary `Data: 2's complement, little endian`
- Compatible with most linux machines `OS/ABI: Unix - System V`
- Target Architecture `Intel 80386`, compiled for `x86` and not for `x86_64/ARM/MIPS`
- Entry point of the executable, "The virtual memory address where execution begins (corresponds to `_start` or the startup routine before `main()`)."
#### Signature check
```bash
readelf -S binary_name | grep -E "sig|signature"
elfsign verify -e ./binary_name
objdump -h binary_name | grep -E "sig|signature"
```

#### nm / nm -D
```bash
# list symbols - static mode
nm lib*.so
# list symbols - dynamic mode
nm -D lib*.so
# demangle the symbols
nm -D --demangle lib*.so
```

#### strings
```bash
strings binary_name | fzf
```

#### strace / ltrace
```bash
# system calls trace
strace binary_name
# library calls trace
ltrace binary_name # -i instruction pointer; -p attach to a process; -C demangle automatically
```

#### objdump
```bash
# section analysis
objdump -s --section .rodata binary_name # .rodata
# assembly instructions
objdump -d binary_name
```

#### gdb / r2
```bash
# start gdb
gdb binary_name
# gdb commands
info functions # ; list all the functions
disass main # ; disassmeble main function
b *memory_address # ; breakpoint
run # ; executes the binary
display/i $pc # ; display instruction at the current program counter
info registers rax # ; inspect the contents of rax register
x/s memory_address # ; inspect stack
quit # ; exit gdb

## advanced
info files # ; symbols, entry points will be listed
set pagination off # ; doesnt breaks the output
set logging on # ; output will be copied to gdb.txt
set logging redirect on # ; output will be redirect to gdb.txt

# start r2
r2 -A binary_name
# r2 commadns
aaa # ; analyze all
afl # ; list functions
info # ; show binary information
pdf @ main # ; disassemble main function
db address # ; breakpoint
dc # ; continue execution
dr  / dr rax # ; show registers / show rax register
dps # ; show program stack
dm / dmm # ; list memory maps
px @ rsp # ; show memory at register pointer
dmp address size # ; dump meomory regision
q # ; quit

## advanced
agg # ; Graph view in CLI 
agf @ main # ; Function graph for 'main'
/ str Secret # ; search for string "Secret" in the binary
/a call # ; searches for 'call' instructions
```

#### cfg
```bash
objdump -d binary_name | awk '/^[[:xdigit:]]+:/ {address=$1} /call|jmp|je|jne|jg|jl|jz|jnz/ {print address, $0}'
# Ghidra -> Display Function Graph
```

#### Ghidra


#### conclusion
```shell
# Section to add what I learnt, what I oberved, what changed
```

## Secured

#### File

#### checksec

#### ldd

#### grep

#### readelf

#### nm / nm -D

#### strings

#### strace / ltrace

#### objdump

#### gdb / r2

#### cfg

#### ghidra

#### conclusion

---
# 64 Bit

## Vulnearble

#### File

#### checksec

#### ldd

#### grep

#### readelf

#### nm / nm -D

#### strings

#### strace / ltrace

#### objdump

#### gdb / r2

#### cfg

#### ghidra

#### conclusion
## Secured

#### File

#### checksec

#### ldd

#### grep

#### readelf

#### nm / nm -D

#### strings

#### strace / ltrace

#### objdump

#### gdb / r2

#### cfg

#### ghidra

#### conclusion