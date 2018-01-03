#!/usr/bin/python3

import ecdsa, struct, time, binascii, hexdump, base64, random, socket, sys, datetime, hashlib, pyasn1, re
from threading import Thread, Timer
from pyasn1.codec.der.encoder import encode
from pyasn1.codec.der.decoder import decode
from select import select
from pyasn1.type import univ, namedtype, tag
from queue import Queue
from Crypto.Cipher import AES
from fastecdsa.curve import P256
from quicklz import decompress
from fastecdsa.point import Point 

class TSConnectException(Exception):
    pass

# Data structure for ASN.1-DER
class PubKey(univ.Sequence):
	componentType = namedtype.NamedTypes(
        namedtype.NamedType('b', univ.BitString("'0'B")),
        namedtype.NamedType('c', univ.Integer(32)),
        namedtype.NamedType('x', univ.Integer(0)),
        namedtype.NamedType('y', univ.Integer(0)),
    )

class Identity:
	def __init__(self, privkey=None, keyoffset=None):
		if privkey is not None:
			priv = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.NIST256p)
			self.keyoffset = keyoffset
		else:
			priv = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
			self.keyoffset = 0

		pub = priv.get_verifying_key()
		pkey = PubKey()
		pkey['x'] = pub.pubkey.point.x()
		pkey['y'] = pub.pubkey.point.y()
		pkey['c'] = 32
		pkey['b'] = "'0'B"
		self.privkey = priv.privkey.secret_multiplier
		self.pubkey = base64.b64encode(encode(pkey))

	def security_level(self):
		hsh = hashlib.sha1()
		hsh.update(self.pubkey + bytes(str(self.keyoffset), 'ascii'))
		hsh = bytearray(hsh.digest())
		
		j = 0
		lvl = 0

		for j in range(0, len(hsh)):
			for k in range(0, 8):
				if (hsh[j] & (1 << k)) == 0:
					lvl += 1
				else:
					return lvl


class TS3Client:
	class PacketType:
		INIT1 = 8

	__defaultKey = bytes(bytearray([0x63, 0x3A, 0x5C, 0x77, 0x69, 0x6E, 0x64, 0x6F, 0x77, 0x73, 0x5C, 0x73, 0x79, 0x73, 0x74, 0x65]))
	__defaultNonce = bytes(bytearray([0x6D, 0x5C, 0x66, 0x69, 0x72, 0x65, 0x77, 0x61, 0x6C, 0x6C, 0x33, 0x32, 0x2E, 0x63, 0x70, 0x6C]))
	

	def __init__(self, identity, server, port, nick):
		self.identity = identity
		self.__endpoint = (server, port)
		self.__sharedIV = None
		self.__nick = nick
		self.__sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.__defaultMac = None
		self.__pgid = 0
		self.__halt = False
		self.__clientID = 0
		self.__pongTries = 0
		self.__lastPong = 0
		self.__sharedMac = None
		self.__packetCounterRecv = [1] * 18
		self.__packetCounter = [1] * 18
		self.__packetQueueTmp = [[]] * 9
		self.__packetQueue = Queue()

		self.channelList = None
		self.clientList = None


	def __bb2html(self, txt):
		txt = re.sb


	def __get_nonce(self, tp, pid, direction):
		tmp = (b'\x31' if direction == 0 else b'\x30') + struct.pack('B', tp) + struct.pack('>I', pid >> 16) + self.__sharedIV

		hsh = hashlib.sha256()
		hsh.update(tmp)
		keynonce = hsh.digest()

		key = bytearray(keynonce[0:16])
		nonce = keynonce[16:32]
		key[0] ^= (pid & 0xFF00) >> 8
		key[1] ^= pid & 0x00FF


		return bytes(key), bytes(nonce)

	def __gen_packet(self, mac, pid, cid, tp, flag_u, flag_c, flag_n, flag_f, payload):
		pack = bytearray()


		pack += struct.pack('>H', pid & 0xFFFF)
		pack += struct.pack('>H', cid)
		pack += struct.pack('B', (flag_u << 7) | (flag_c << 6) | (flag_n << 5) | (flag_f << 4) | tp)

		if flag_u == 0:
			if self.__sharedIV == None:
				key = self.__defaultKey
				nonce = self.__defaultNonce
			else:
				key, nonce = self.__get_nonce(tp, pid, 0)

			cipher = AES.new(key, AES.MODE_EAX, nonce=nonce, mac_len=8)
			cipher.update(bytes(pack[0:5]))
			payload, mac = cipher.encrypt_and_digest(payload)
		elif mac == None:
			mac = self.__sharedMac

		pack = mac + pack

		return pack + payload

	def __xor(self, a, b):
		return bytes(bytearray([a[i]^b[i] for i in range(0, len(a))]))

	def __packetLoop(self):
		try: 
			while not self.__halt:
				_r, _w, _e = select([self.__sock], [], [self.__sock], 1)

				if self.__sock in _e:
					return
				elif self.__sock not in _r:
					continue

				res = self.__parse_packet(self.__sock.recvfrom(512)[0])
				q = self.__packetQueueTmp[res['tp']]

				if res['tp'] == 6:
					continue
				elif res['tp'] == 5:
					self.__lastPong = time.time()
					continue

				if res['tp'] < 8 and res['pid'] > 0:
					if self.__packetCounterRecv[res['tp']] != res['pid'] and res['tp'] != 4:
						continue
					else:
						if self.__packetCounterRecv[res['tp']] != res['pid']:
							self.__packetCounterRecv[res['tp']] = res['pid']

						self.__packetCounterRecv[res['tp']] += 1

						if res['tp'] == 4 or res['tp'] == 2:
							self.__send_packet(None, self.__packetCounter[6 if res['tp'] == 2 else 5], self.__clientID, 6 if res['tp'] == 2 else 5, 1 if res['tp'] == 4 else 0, 0, 1 if res['tp'] == 2 else 0, 0, struct.pack('>H', res['pid'] & 0xFFFF))
							self.__packetCounter[6 if res['tp'] == 2 else 5] += 1
				
				if res['tp'] == 3:
					self.__send_packet(None, self.__packetCounter[7], self.__clientID, 7, 0, 0, 0, 0, struct.pack('>H', res['pid'] & 0xFFFF))
					self.__packetCounter[7] += 1

				if res['tp'] == 4:
					continue


				if len(q) > 0:
					q.append(res)

					if res['flag_f'] == 1:
						payload = decompress(b''.join([i['payload'] for i in q])) if q[0]['flag_c'] == 1 else b''.join([i['payload'] for i in q])
						res = q[0]
						res['payload'] = payload
						self.__packetQueue.put(res)

						del q[:]
				else:
					if res['flag_f'] == 1:
						q.append(res)
					else:
						if res['flag_c'] == 1:
							res['payload'] = decompress(res['payload'])

						self.__packetQueue.put(res)

		except:
			raise
			return

		print('Returned normally')

	def __parse_packet(self, payload):
		res = {
			'mac':		bytes(payload[0:8]),
			'pid':		struct.unpack('>H', payload[8:10])[0],
			'tp':		struct.unpack('B', payload[10:11])[0] & 15,
			'flag_u':   (struct.unpack('B', payload[10:11])[0] & (1 << 7)) >> 7,
			'flag_c':   (struct.unpack('B', payload[10:11])[0] & (1 << 6)) >> 6,
			'flag_n':   (struct.unpack('B', payload[10:11])[0] & (1 << 5)) >> 5,
			'flag_f':   (struct.unpack('B', payload[10:11])[0] & (1 << 4)) >> 4,
			'payload':	payload[11:]
		}


		if res['flag_c'] == 1:
			res['payload'] = res['payload']

		if res['flag_u'] == 0:
			if self.__sharedIV == None:
				key = self.__defaultKey
				nonce = self.__defaultNonce
			else:
				key, nonce = self.__get_nonce(res['tp'], res['pid'], 1)

			cipher = AES.new(key, AES.MODE_EAX, nonce=nonce, mac_len=8)
			cipher.update(payload[8:11])

			try:
				res['payload'] = cipher.decrypt_and_verify(res['payload'], res['mac'])
			except Exception:
				print('ERROR')

		return res

	def ping(self):
		if self.__halt:
			return

		Timer(30.0, self.ping).start()

		if self.__lastPong == 0 and self.__pongTries > 1:
			self.disconnect()
			return

		if self.__sharedMac == None:
			self.__pongTries += 1
			return

		self.__send_packet(None, self.__packetCounter[2], self.__clientID, 2, 0, 0, 1, 0, b'connectioninfoautoupdate connection_server2client_packetloss_speech=0.0000 connection_server2client_packetloss_keepalive=0.0000 connection_server2client_packetloss_control=0.0000 connection_server2client_packetloss_total=0.0000')
		self.__packetCounter[2] += 1
		self.__send_packet(None, self.__packetCounter[2], self.__clientID, 4, 1, 0, 0, 0, b'')
		self.__packetCounter[4] += 1

		if self.__lastPong > 0 and time.time() - self.__lastPong > 45:
			print('Ping timeout, disconnecting...')
			self.disconnect()
		elif self.__lastPong == 0:
			self.__pongTries += 1

	def __parse_params(self, string, utf8=False):
		elements = re.split(br'(?<!\\)(?:\\\\)*\|', string)

		r = []

		for stri in elements:
			split = stri.split(b' ')

			data = {}

			for i in split:
				if b'=' in i:
					if not utf8:
						data[i.split(b'=', 1)[0].decode('ascii')] = i.split(b'=', 1)[1]
					else:
						data[i.split(b'=', 1)[0].decode('ascii')] = i.split(b'=', 1)[1].decode('latin1').replace('\s', ' ').replace('\/', '/').replace('\\n', "\n")

			r.append(data)

		if len(r) < 2:
			return r[0]
		else:
			return r

	def __input_loop(self):
		while not self.__halt:
			cmd = input(">>> [clid= " + str(self.__clientID) + "] ")

			self.__send_packet(None, self.__packetCounter[2], self.__clientID, 2, 0, 0, 1, 0, bytes(cmd, 'ascii'))
			self.__packetCounter[2] += 1

	def __send_packet(self, mac, pid, cid, tp, flag_u, flag_c, flag_n, flag_f, payload):
		try:
			self.__sock.sendto(self.__gen_packet(mac, pid, cid, tp, flag_u, flag_c, flag_n, flag_f, payload), self.__endpoint)
		except KeyboardInterrupt:
			raise
		except:
			return

	def __wait_packet(self, tp=None):
		while True:
			elem = self.__packetQueue.get()

			if elem == []:
				raise TSConnectException

			if tp == None or elem['tp'] == tp:
				return elem


	def interactive(self, verbose=False):
		try:
			inputThread = Thread(target=self.__input_loop)
			inputThread.start()

			while not self.__halt:
				res = self.__wait_packet()

				if 'payload' not in res:
					return

				if verbose:
					print(res['payload'])

				if res['payload'].startswith(b'clid='):
					res['payload'] = b'clientlist ' + res['payload']

				cmd = res['payload'].split(b' ', 1)

				if len(cmd) > 1:
					data = self.__parse_params(cmd[1], utf8=True)

				if cmd[0] == b'notifyconnectioninforequest':	
					self.__send_packet(None, self.__packetCounter[2], self.__clientID, 2, 0, 0, 1, 0, b'setconnectioninfo connection_ping=295.0000 connection_ping_deviation=50.6773 connection_packets_sent_speech=0 connection_packets_sent_keepalive=174 connection_packets_sent_control=237 connection_bytes_sent_speech=0 connection_bytes_sent_keepalive=7308 connection_bytes_sent_control=14486 connection_packets_received_speech=0 connection_packets_received_keepalive=174 connection_packets_received_control=233 connection_bytes_received_speech=0 connection_bytes_received_keepalive=7134 connection_bytes_received_control=47897 connection_server2client_packetloss_speech=0.0000 connection_server2client_packetloss_keepalive=0.0000 connection_server2client_packetloss_control=0.0000 connection_server2client_packetloss_total=0.0000 connection_bandwidth_sent_last_second_speech=0 connection_bandwidth_sent_last_second_keepalive=84 connection_bandwidth_sent_last_second_control=490 connection_bandwidth_sent_last_minute_speech=0 connection_bandwidth_sent_last_minute_keepalive=83 connection_bandwidth_sent_last_minute_control=87 connection_bandwidth_received_last_second_speech=0 connection_bandwidth_received_last_second_keepalive=82 connection_bandwidth_received_last_second_control=107 connection_bandwidth_received_last_minute_speech=0 connection_bandwidth_received_last_minute_keepalive=81 connection_bandwidth_received_last_minute_control=202')
					self.__packetCounter[2] += 1

				if cmd[0] == b'notifycliententerview':
					if self.clientList is None:
						self.clientList = {}

					if isinstance(data, dict) and 'clid' in data:
						self.clientList[data['clid']] = data
				elif cmd[0] == b'channellist':
					if self.channelList is None:
						self.channelList = {}
					
					for c in data if isinstance(data, list) else [data]:
						self.channelList[c['cid']] = c

				elif cmd[0] == b'clientlist':
					if self.clientList is None:
						self.clientList = {}
					
					for c in data if isinstance(data, list) else [data]:
						self.clientList[c['clid']] = c

				elif cmd[0] == b'channellistfinished':
					self.__send_packet(None, self.__packetCounter[2], self.__clientID, 2, 0, 0, 1, 0, bytes('clientlist', 'ascii'))
					self.__packetCounter[2] += 1
				else:
					pass
					#print(cmd)
		except KeyboardInterrupt:
			self.disconnect()
			raise
		except:
			self.disconnect()
			raise

	def get_channel_description(self, cid):		
		cidbytes = bytes(str(cid), 'ascii')
		self.__send_packet(None, self.__packetCounter[2], self.__clientID, 2, 0, 0, 1, 0, b'channelgetdescription cid=' + cidbytes)
		self.__packetCounter[2] += 1

		while True:
			res = self.__wait_packet()

			if res['tp'] == 3 and res['payload'].startswith(b'notifychanneledited cid=' + cidbytes):
				p = self.__parse_params(res['payload'], utf8=True)

				return p['channel_description']

	def disconnect(self):
		print('Disconnecting')
		self.__send_packet(None, self.__packetCounter[2], self.__clientID, 2, 0, 0, 1, 0, b'clientdisconnect')
		self.__halt = True
		self.__sock.close()
		self.__packetQueue.put([])

	def moveto(self, cid):
		clidbytes = bytes(str(self.__clientID), 'ascii')
		cidbytes = bytes(str(cid), 'ascii')

		self.__send_packet(None, self.__packetCounter[2], self.__clientID, 2, 0, 0, 1, 0, b'clientmove clid=' + clidbytes + b' cid=' + cidbytes)

	def connect(self):
		try:
			print('Connecting')
			self.__halt = False
			thread = Thread(target=self.__packetLoop)
			thread.start()

			self.ping()

			self.__packetThread = thread

			self.__send_packet(b'TS3INIT1', 101, 0,   8,  1, 0, 1, 0, bytearray([0x06, 0x3b, 0xec, 0xe9, 0x00]) + struct.pack('I', int(time.time())) + b'flub' + b'\x00' * 8)

			res = self.__wait_packet(self.PacketType.INIT1)
			self.__send_packet(b'TS3INIT1', 101, 0,    8, 1, 0, 1, 0, bytearray([0x56, 0x28, 0xc5, 0x28, 0x02]) + res['payload'][1:21])

			res = self.__wait_packet(self.PacketType.INIT1)

			x = int.from_bytes(res['payload'][1:65], byteorder='big')
			n = int.from_bytes(res['payload'][65:129], byteorder='big')
			level = struct.unpack('>I', res['payload'][129:133])[0]

			# Solution for RSA puzzle
			calc = pow(x, pow(2, level), n)


			alpha = base64.b64encode(bytearray([random.randint(0,128) for i in range(0, 10)]))

			self.__send_packet(b'TS3INIT1', 101, 0,    8, 1, 0, 0, 0, bytearray([0x06, 0x3b, 0xec, 0xe9, 0x04]) + res['payload'][1:233] + calc.to_bytes((calc.bit_length() + 7) // 8, 'big') +  b'clientinitiv alpha=' + alpha + b' omega=' + self.identity.pubkey + b' ot=1 ip=217.114.218.23')

			self.__send_packet(None,  0,   0, 2, 0, 0, 1, 0, b'clientinitiv alpha=' + alpha + b' omega=' + self.identity.pubkey + b' ot=1 ip')

			res = self.__wait_packet()

			tmp = self.__parse_params(res['payload'])
			omega_ = decode(base64.b64decode(tmp['omega']))
			beta = base64.b64decode(tmp['beta'])

			srvpubkey = Point(int(omega_[0][2]), int(omega_[0][3]), curve=P256)
			sharedSecret = (srvpubkey * self.identity.privkey)
			x = sharedSecret.x.to_bytes((sharedSecret.x.bit_length() + 7) // 8, 'big')

			hsh = hashlib.sha1()

			hsh.update(b'\x00' * max(0, 32 - len(x)) + x[max(32, len(x))-32:len(x)])
			sharedIV = hsh.digest()
			self.__sharedIV = self.__xor(sharedIV[0:10], base64.b64decode(alpha)) + self.__xor(sharedIV[10:20], beta)

			hsh = hashlib.sha1()
			hsh.update(self.__sharedIV)
			self.__sharedMac = hsh.digest()[0:8]

			self.__send_packet(None, self.__packetCounter[2], 0, 2, 0, 0, 1, 0, b'clientinit client_nickname=' + self.__nick + b' client_version=3.1.6\\s[Build:\\s1502873983] client_platform=Windows client_input_hardware=1 client_output_hardware=1 client_default_channel client_default_channel_password client_server_password client_meta_data client_version_sign=o+l92HKfiUF+THx2rBsuNjj/S1QpxG1fd5o3Q7qtWxkviR3LI3JeWyc26eTmoQoMTgI3jjHV7dCwHsK1BVu6Aw== client_key_offset=' + bytes(str(self.identity.keyoffset), 'ascii') + b' client_away=0 client_nickname_phonetic client_default_token client_badges=Overwolf=1 hwid')

			res = self.__wait_packet()
			self.__packetCounter[2] += 1

			settings = self.__parse_params(res['payload'], utf8=True)

			if not 'aclid' in settings:
				print('Error connecting')
				print(settings)
				self.disconnect()
				return

			self.__clientID = int(settings['aclid'])

			self.__send_packet(None, self.__packetCounter[2], self.__clientID, 2, 0, 0, 1, 0, b'channelsubscribeall')
			self.__packetCounter[2] += 1
		except TSConnectException:
			return

		print('Connected')
			
		self.__send_packet(None, self.__packetCounter[2], self.__clientID, 2, 0, 0, 1, 0, bytes('channellist', 'ascii'))
		self.__packetCounter[2] += 1




