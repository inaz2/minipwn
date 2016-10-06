from minipwn import *

s = connect_process(['/bin/sh'])
sendline(s, 'id')
print "%r" % recvline(s)
disconnect(s)
