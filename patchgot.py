import sys
import struct
from subprocess import check_output

def patchgot(fpath, funcname):
    with open(fpath) as f:
        data = f.read()

    signature = data[:6]
    if signature == '\x7fELF\x01\x01':
        wordsize = 4
        print "[+] file is ELF32 little endian"
    elif signature == '\x7fELF\x02\x01':
        wordsize = 8
        print "[+] file is ELF64 little endian"
    else:
        raise Exception('unsupported file')

    result = check_output(['objdump', '-d', fpath])
    for line in reversed(result.splitlines()):
        if "<%s@plt>:" % funcname in line:
            gotdst = line.split()[0]
            gotdst = int(gotdst, 16) + 6
        if 'c3                   \tret' in line:
            addr_ret = line.split(':', 1)[0]
            addr_ret = int(addr_ret.strip(), 16)

    print "[+] patch gotdst = %x pointing to addr_ret = %x" % (gotdst, addr_ret)
    if wordsize == 4:
        x = struct.pack('<I', gotdst)
        y = struct.pack('<I', addr_ret)
        outdata = data.replace(x, y)
    elif wordsize == 8:
        x = struct.pack('<Q', gotdst)
        y = struct.pack('<Q', addr_ret)
        outdata = data.replace(x, y)

    check_output(['cp', fpath, fpath+'.orig'])
    with open(fpath, 'wb') as f:
        f.write(outdata)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print >>sys.stderr, "Usage: python %s FILE FUNCNAME" % sys.argv[0]
        sys.exit(1)
    fpath = sys.argv[1]
    funcname = sys.argv[2]
    patchgot(fpath, funcname)
