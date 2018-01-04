#!/usr/bin/python3

import ecdsa, struct, time, binascii, base64, random, socket, sys, datetime, hashlib, pyasn1
from threading import Thread
from pyasn1.codec.der.encoder import encode
from pyasn1.codec.der.decoder import decode
from pyasn1.type import univ, namedtype, tag
from fastecdsa.curve import P256
from fastecdsa.point import Point 

curve = ecdsa.NIST256p

# Use this line to generate a new identity
key = ecdsa.SigningKey.generate(curve=curve)

# Uncomment this line to use an existing identity and provide your key offset to continue from
#key = ecdsa.SigningKey.from_string(b'f\xef\xbam\xcb\x88\x1e\x9a\xbf\xa8l\x81\x7f\xdf]\xd0\x84\xe7/J\xc3N\xca\xca;x\x95c\xca\x8e\x80\xf4', curve=curve)
keyoffset  = 0



# Data structure for ASN.1-DER
class PubKey(univ.Sequence):
	componentType = namedtype.NamedTypes(
        namedtype.NamedType('b', univ.BitString("'0'B")),
        namedtype.NamedType('c', univ.Integer(32)),
        namedtype.NamedType('x', univ.Integer(0)),
        namedtype.NamedType('y', univ.Integer(0))
    )


pubkey = key.get_verifying_key()

pkey = PubKey()
pkey['x'] = pubkey.pubkey.point.x()
pkey['y'] = pubkey.pubkey.point.y()
pkey['c'] = 32
pkey['b'] = "'0'B"

print(key.to_string())

i = 0
mx = 0
omega = base64.b64encode(encode(pkey))


def get_security(omega, i):
	hsh = hashlib.sha1()
	hsh.update(omega + bytes(str(i), 'ascii'))
	hsh = bytearray(hsh.digest())
	
	j = 0
	lvl = 0

	for j in range(0, len(hsh)):
		for k in range(0, 8):
			if (hsh[j] & (1 << k)) == 0:
				lvl += 1
			else:
				return lvl

mx = get_security(omega, keyoffset)


def improve_security(i, offset):
	try:
		print("Thread " + str(offset) + " started")
		global mx
		i += offset
		while True:
			i += 11	

			lvl = get_security(omega, i)

			if mx < lvl:
				mx = lvl
				print('new security level: ' + str(mx) + ' at ' + str(i))
				keyoffset = i

	except KeyboardInterrupt:
		print(keyoffset, i)
		sys.exit()

Thread(target=improve_security, args=(i, 0)).start()
Thread(target=improve_security, args=(i, 1)).start()
Thread(target=improve_security, args=(i, 2)).start()
Thread(target=improve_security, args=(i, 4)).start()
Thread(target=improve_security, args=(i, 5)).start()
Thread(target=improve_security, args=(i, 6)).start()
Thread(target=improve_security, args=(i, 7)).start()
Thread(target=improve_security, args=(i, 8)).start()
Thread(target=improve_security, args=(i, 9)).start()
Thread(target=improve_security, args=(i, 10)).start()
t = Thread(target=improve_security, args=(i, 3))
t.start()
t.join()
