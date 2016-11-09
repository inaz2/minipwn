import sys
import re
import struct

def get_exec_bytes(fpath):
    with open(fpath, 'rb') as f:
        data = f.read()
    if data[:4] != "\177ELF":
        raise Exception("not ELF file")

    ei_class = ord(data[4])
    if ei_class == 1:
        tmp = data[:0x34]
        elf32_hdr = struct.unpack('<16sHHIIIIIHHHHHH', tmp)
        e_phoff, e_phentsize, e_phnum = elf32_hdr[5], elf32_hdr[9], elf32_hdr[10]
        for i in xrange(e_phnum):
            tmp = data[e_phoff+e_phentsize*i:e_phoff+e_phentsize*(i+1)]
            elf32_phdr = struct.unpack('<IIIIIIII', tmp)
            p_type, p_offset, p_vaddr, p_filesz, p_flags = elf32_phdr[0], elf32_phdr[1], elf32_phdr[2], elf32_phdr[4], elf32_phdr[6]
            if p_type == 1 and p_flags & 1:
                return data[p_offset:p_offset+p_filesz], p_vaddr
    elif ei_class == 2:
        tmp = data[:0x40]
        elf64_hdr = struct.unpack('<16sHHIQQQIHHHHHH', tmp)
        e_phoff, e_phentsize, e_phnum = elf64_hdr[5], elf64_hdr[9], elf64_hdr[10]
        for i in xrange(e_phnum):
            tmp = data[e_phoff+e_phentsize*i:e_phoff+e_phentsize*(i+1)]
            elf64_phdr = struct.unpack('<IIQQQQQQ', tmp)
            p_type, p_flags, p_offset, p_vaddr, p_filesz = elf64_phdr[0], elf64_phdr[1], elf64_phdr[2], elf64_phdr[3], elf64_phdr[5]
            if p_type == 1 and p_flags & 1:
                return data[p_offset:p_offset+p_filesz], p_vaddr
    else:
        raise Exception("unsupported ELF class")


def get_index(offset, data, s):
    try:
        return hex(offset + data.index(s))
    except ValueError:
        return None

def get_index_re(offset, data, regexp):
    m = re.search(regexp, data)
    if m:
        return hex(offset + m.start())
    else:
        return None

def print_gadgets(fpath):
    data, offset = get_exec_bytes(fpath)

    gadgets = [
        ('pop_rbp', '\x5d\xc3'),
        ('leave', '\xc9\xc3'),
        ('ret', '\xc3'),
        ('xchg_esp_eax', '\x94\xc3'),
        ('jmp_rsp', '\xff\xe4'),
        ('call_rsp', '\xff\xd4'),
        ('pop_rax', '\x58\xc3'),
        ('pop_rbx', '\x5b\xc3'),
        ('pop_rcx', '\x59\xc3'),
        ('pop_rdx', '\x5a\xc3'),
        ('pop_rdi', '\x5f\xc3'),
        ('pop_rsi', '\x5e\xc3'),
        ('int80', '\xcd\x80'),
        ('syscall', '\x0f\x05'),
        ('csu_init1', '\x48\x83\xc4\x08\x5b\x5d\x41\x5c\x41\x5d\x41\x5e\x41\x5f\xc3'),
        ('csu_init2', '\x4c\x89\xea\x4c\x89\xf6\x44\x89\xff\x41\xff\x14\xdc\x48\x83\xc3\x01\x48\x39\xeb\x75\xea'),
    ]
    for k, v in gadgets:
        print "addr_%s = %s" % (k, get_index(offset, data, v))

    gadgets_re = [
        ('pop1', r'[\x58-\x5b\x5d-\x5f]\xc3'),
        ('pop2', r'[\x58-\x5b\x5d-\x5f]{2}\xc3'),
        ('pop3', r'[\x58-\x5b\x5d-\x5f]{3}\xc3'),
        ('pop4', r'[\x58-\x5b\x5d-\x5f]{4}\xc3'),
    ]
    for k, v in gadgets_re:
        print "addr_%s = %s" % (k, get_index_re(offset, data, v))


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print >>sys.stderr, "Usage: python %s PATH" % sys.argv[0]
        sys.exit(1)
    print_gadgets(sys.argv[1])
