# 32 Bit

## Vulnerable

#### File
```bash
file binary_name
```

#### checksec
```bash
pwn checksec binary_name
```

#### ldd
```bash
ldd binary_name
```

#### readelf
```bash
# elf metadata
readelf -h binary_name
# library fil meta data
readelf -hs lib*.so
```

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