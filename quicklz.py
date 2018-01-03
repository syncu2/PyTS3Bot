import base64

def header_len(src):
	return 9 if (src[0] & 2) == 2 else 3


def size_decompressed(src):
	if header_len(src) == 9:
		return fast_read(src, 5, 4)
	else:
		return fast_read(source, 2, 1)

def fast_read(a, i, numBytes):
	l = 0

	for j in range(0, numBytes):
		l |= ((a[i + j]) & 0xff) << j * 8

	return l


def decompress(source):
	source = bytearray(source)
	size = size_decompressed(source)
	src = header_len(source)
	dst = 0
	cword_val = 1
	destination = bytearray(b'\x00' * size)
	hashtable = [0 for i in range(0,4096)]
	hash_counter = bytearray(b'\x00' * 4096)
	last_matchstart = size - 11
	last_hashed = -1
	hash_ = 0
	fetch = 0

	level = (source[0] >> 2) & 0x3

	if source[0] & 1 != 1:
		return source[src:src+size]

	while True:
		if cword_val == 1:
			cword_val = fast_read(source, src, 4)
			src += 4

			if dst <= last_matchstart:
				if level == 1:
					fetch = fast_read(source, src, 3)
				else:
					fetch = fast_read(source, src, 4)



		if (cword_val & 1) == 1:
			matchlen = 0
			offset2 = 0

			cword_val = cword_val >> 1

			if level == 1:
				hash_ = (fetch >> 4) & 0xfff
				offset2 = hashtable[hash_]

				if (fetch & 0xf) != 0:
					matchlen = (fetch & 0xf) + 2
					src += 2
				else:
					matchlen = source[src + 2] & 0xff
					src += 3
			else:
				offset = 0

				if fetch & 3 == 0:
					offset = (fetch & 0xff) >> 2
					matchlen = 3
					src+=1
				elif fetch & 2 == 0:
					offset = (fetch & 0xffff) >> 2
					matchlen = 3
					src += 2
				elif fetch & 1 == 0:
					offset = (fetch & 0xffff) >> 6
					matchlen = ((fetch >> 2) & 15) + 3
					src += 2
				elif fetch & 127 != 3:
					offset = (fetch >> 7) & 0x1ffff
					matchlen = ((fetch >> 2) & 0x1f) + 2
					src += 3
				else:
					offset = fetch >> 15
					matchlen = ((fetch >> 7) & 255) + 3
					src += 4

				offset2 = dst - offset

			destination[dst + 0] = destination[offset2 + 0]
			destination[dst + 1] = destination[offset2 + 1]
			destination[dst + 2] = destination[offset2 + 2]

			for i in range(3, matchlen):
				destination[dst + i] = destination[offset2 + i]

			dst += matchlen

			if level == 1:
				fetch = fast_read(destination, last_hashed + 1, 3)

				while last_hashed < dst - matchlen:
					last_hashed+=1
					hash_ = ((fetch >> 12) ^ fetch) & 4095
					hashtable[hash_] = last_hashed
					hash_counter[hash_] = 1
					fetch = fetch >> 8 & 0xffff | ((destination[last_hashed + 3]) & 0xff) << 16

				fetch = fast_read(source, src, 3)
			else:
				fetch = fast_read(source, src, 4)


			last_hashed = dst - 1
		else:		
			if dst <= last_matchstart:
				destination[dst] = source[src]
				dst += 1
				src += 1
				cword_val = cword_val >> 1

				if level == 1:
					while last_hashed < dst - 3:
						last_hashed+=1
						fetch2 = fast_read(destination, last_hashed, 3)
						
						hash_ = ((fetch2 >> 12) ^ fetch2) & 4095
					
						hashtable[hash_] = last_hashed
						hash_counter[hash_] = 1

		
					fetch = fetch >> 8 & 0xffff | ((source[src + 2]) & 0xff) << 16
					
				else:
					fetch = fetch >> 8 & 0xffff | ((source[src + 2]) & 0xff) << 16 | ((source[src + 3]) & 0xff) << 24
			else:

				while dst <= size - 1:
					if cword_val == 1:
						src += 4
						cword_val = 0x80000000

					destination[dst] = source[src]
					dst+=1
					src+=1

					cword_val = cword_val >> 1


				return destination
