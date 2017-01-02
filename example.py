from minipwn import *

s = connect_process(['/bin/pwd'])
#s = socket.create_connection(('localhost', 4444))

data = recvline(s)
print "%r" % data

interact(s)
