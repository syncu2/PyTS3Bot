#!/usr/bin/python3

from pyts3bot import Identity, TS3Client

# Insert your key string and key offset here

i = Identity(privkey=b'f\xef\xbam\xcb\x88\x1e\x9a\xbf\xa8l\x81\x7f\xdf]\xd0\x84\xe7/J\xc3N\xca\xca;x\x95c\xca\x8e\x80\xf4'
, keyoffset=5498950)


#                       TS IP            Port    Nickname
client = TS3Client(i, 'xxx.xxx.xxx.xxx', 9987, b'yournickname')
client.connect()

# Start interactive mode
client.interactive(verbose=True)
