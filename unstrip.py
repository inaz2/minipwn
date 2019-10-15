import sys
import re
import struct
from subprocess import check_output

def get_exec_bytes(fpath):
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
            p_type, p_offset, p_vaddr, p_filesz, p_flags = elf32_phdr[0], elf32_phdr[1], elf32_phdr[2], elf32_phdr[4], elf32_phdr[6]
            if p_type == 1 and p_flags & 1:
                return data[p_offset:p_offset+p_filesz], p_vaddr
    elif ei_class == 2:
        tmp = data[:0x40]
        elf64_hdr = struct.unpack('<16sHHIQQQIHHHHHH', tmp)
        e_phoff, e_phentsize, e_phnum = elf64_hdr[5], elf64_hdr[9], elf64_hdr[10]
        for i in range(e_phnum):
            tmp = data[e_phoff+e_phentsize*i:e_phoff+e_phentsize*(i+1)]
            elf64_phdr = struct.unpack('<IIQQQQQQ', tmp)
            p_type, p_flags, p_offset, p_vaddr, p_filesz = elf64_phdr[0], elf64_phdr[1], elf64_phdr[2], elf64_phdr[3], elf64_phdr[5]
            if p_type == 1 and p_flags & 1:
                return data[p_offset:p_offset+p_filesz], p_vaddr
    else:
        raise Exception("unsupported ELF class")

def get_so_offsets(sopath):
    result = check_output(['nm', '-D', sopath]).decode('latin1')
    so_offsets = []
    for line in result.splitlines():
        ary = line.split()
        if len(ary) != 3 or ary[1] not in ('T', 'W'):
            continue
        so_offsets.append((ary[2], int(ary[0], 16)))
    return sorted(so_offsets)

def get_index(data, s, start=0):
    offset = data[start:].index(s)
    return start+offset

def unstrip(fpath, sopath):
    so_offsets = get_so_offsets(sopath)

    data, offset = get_exec_bytes(fpath)
    with open(sopath, 'rb') as f:
        so_data = f.read()

    for k, v in so_offsets:
        # signature is from the beginning to call (0xe8), near jump (0xe9) or ret (0xc3)
        m = re.search(r'^[^\xe8\xe9\xc3]{4,}.', so_data[v:].decode('latin1'), re.DOTALL)
        if m:
            signature = m.group(0).encode('latin1')
        else:
            continue
        try:
            # functions are on 16 byte boundaries
            index = get_index(data, signature)
            while index % 16 != 0:
                index = get_index(data, signature, index+1)
        except ValueError:
            continue
        print("{} = {}".format(k, hex(offset+index)))

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python {} PATH SO_PATH".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)
    unstrip(sys.argv[1], sys.argv[2])
