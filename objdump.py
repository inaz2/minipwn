import sys
import re
import struct
import codecs
from subprocess import check_output

def load_strings(fpath):
    strings = {}

    with open(fpath, 'rb') as f:
        data = f.read()
    if data[:4] != b"\177ELF":
        raise Exception("not ELF file")

    ei_class = data[4]
    if ei_class == 1:
        tmp = data[:0x34]
        elf32_hdr = struct.unpack('<16sHHIIIIIHHHHHH', tmp)
        e_phoff, e_phentsize, e_phnum = elf32_hdr[5], elf32_hdr[9], elf32_hdr[10]
        for i in range(e_phnum):
            tmp = data[e_phoff+e_phentsize*i:e_phoff+e_phentsize*(i+1)]
            elf32_phdr = struct.unpack('<IIIIIIII', tmp)
            p_type, p_offset, p_vaddr, p_filesz = elf32_phdr[0], elf32_phdr[1], elf32_phdr[2], elf32_phdr[4]
            if p_type == 1:
                tmp = data[p_offset:p_offset+p_filesz].decode('latin1')
                for m in re.finditer(r'([\s\x21-\x7e]{2,})\x00', tmp):
                    strings[p_vaddr+m.start()] = m.group(1)
    elif ei_class == 2:
        tmp = data[:0x40]
        elf64_hdr = struct.unpack('<16sHHIQQQIHHHHHH', tmp)
        e_phoff, e_phentsize, e_phnum = elf64_hdr[5], elf64_hdr[9], elf64_hdr[10]
        for i in range(e_phnum):
            tmp = data[e_phoff+e_phentsize*i:e_phoff+e_phentsize*(i+1)]
            elf64_phdr = struct.unpack('<IIQQQQQQ', tmp)
            p_type, p_offset, p_vaddr, p_filesz = elf64_phdr[0], elf64_phdr[2], elf64_phdr[3], elf64_phdr[5]
            if p_type == 1:
                tmp = data[p_offset:p_offset+p_filesz].decode('latin1')
                for m in re.finditer(r'([\s\x21-\x7e]{2,})\x00', tmp):
                    strings[p_vaddr+m.start()] = m.group(1)
    else:
        raise Exception("unsupported ELF class")

    return strings

def objdump(fpath):
    strings = load_strings(fpath)
    lines = check_output(['objdump', '-M', 'intel', '-d', fpath]).decode('latin1').splitlines()

    subs = []
    locs = []
    for line in lines:
        m = re.search(r'(call|j\w{1,2})\s+([\da-f]{3,})', line)
        if m:
            addr = int(m.group(2), 16)
            if m.group(1) == 'call':
                subs.append(addr)
            else:
                locs.append(addr)

    for line in lines:
        m = re.search(r'^\s+([\da-f]{3,}):', line)
        if m:
            addr = int(m.group(1), 16)
            if addr in subs:
                print("sub_{:x}:".format(addr))
            if addr in locs:
                print("loc_{:x}:".format(addr))

        annotations = []
        for m in re.finditer(r'0x[\da-f]{3,}', line):
            addr = int(m.group(0), 16)
            if addr in strings:
                annotations.append(repr(strings[addr]))
        for m in re.finditer(r',0x([\da-f]{4,})', line):
            hexstr = m.group(1)
            if len(hexstr) % 2 != 0:
                continue
            s = codecs.decode(hexstr, 'hex')[::-1].decode('latin1')
            if re.search(r'^[\n\x20-\x7e]+$', s):
                annotations.append(repr(s))
        for m in re.finditer(r'^\s+([\da-f]{3,}):.+?j\w{,2}\s+([\da-f]{3,})', line):
            loc = int(m.group(1), 16)
            addr = int(m.group(2), 16)
            if addr < loc:
                annotations.append('backward jump')

        if annotations:
            print(line.ljust(70) + '  ; ' + ', '.join(annotations))
        else:
            print(line)

        if line.endswith('\tret    '):
            print('-' * 80)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python {} PATH".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)
    objdump(sys.argv[1])
