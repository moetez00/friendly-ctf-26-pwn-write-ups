from pwn import*
context.arch="amd64"
import shutil

# This resolves the absolute path (e.g., /usr/bin/kitty) and tricks pwntools into ignoring it
context.terminal = [shutil.which('kitty'), 'sh', '-c']
b="./main"
#l = libc = ELF("./libc.so.6")
elf = e = context.binary = ELF(b)
DEBUG=1 # 0 remote , 1 local , 2 local + gdb
nc="nc localhost 9000"
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




p.sendline(b"\x00abcdefghijklmnop")
"""
tbh i forgot to solve this chall xD
the main idea is to overwrite puts got entry so call system("/bin/sh")
sprintf to change basic offsets, 
sprintf overwrites the first 12 bytes so we should  put \x00 in the fisrt 5 bytes to bypass strlen then to 12 bytes to skip
"your text: " of sprintf
then overwrite got entry using format string, u need fist to leak libc, we can overwrite got entry of exit() with main() 
so we get infinity of overwrites. 
we can run system("your text : || /bin/sh\x00") to bypass "your text :" error.
this is all theorically i didn't try it but it should be fine

i also generated solver using ai i hope it's helpful.

"""
p.interactive()