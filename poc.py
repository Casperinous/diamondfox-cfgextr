import sys
import yara
import vb
import vb.analyzer
import pefile
import struct
import base64
import binascii
import zlib
from Crypto.Cipher import AES

# AESCipher taken from here: https://gist.github.com/h0rn3t/4216cf787b43060b5afc2d50086918bc
# Padding for the input string --not
# related to encryption itself.
BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


class AESCipher:
    """
    Usage:
        c = AESCipher('password').encrypt('message')
        m = AESCipher('password').decrypt(c)
    Tested under Python 3 and PyCrypto 2.6.1.
    """

    def __init__(self, key):
        key = bytearray(key, 'utf-8')
        self.key = key

    def encrypt(self, raw):
        raw = pad(raw)
        cipher = AES.new(self.key, AES.MODE_ECB)
        return base64.b64encode(cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_ECB)
        data = cipher.decrypt(enc)
        return data


class Data:

    def __init__(self, pe, vba, obj_table, proj_data2):
        self.pe = pe
        self.vba = vba
        self.data = {}
        self._init_map(obj_table, proj_data2)

    def _init_map(self, obj_table, proj_data2):

        for pub_obj in self.vba.get_public_object_descriptors(obj_table, proj_data2):
            obj_info = self.vba.get_object_info(pub_obj)
            if obj_info.lpConstants not in self.data:
                self._init_bound_entry(obj_info.lpConstants)

            for proc in self.vba.get_proc_desc_info(obj_info):
                self._check_bounds(obj_info.lpConstants, proc.addr, proc.size)
                
    def _check_bounds(self, addr, proc_addr, sz):

        if addr in self.data:
            l,u = self.data[addr]

            if proc_addr < l:
                self.data[addr][0] = proc_addr

            if proc_addr + sz > u:
                self.data[addr][1] = proc_addr + sz

    def _get_const_addr(self,va):
        for i in self.data:
            if va > self.data[i][0] and va < self.data[i][1]:
                return i
        return None

    def _is_va(self, va):
        if va < 0x00400000:
            va = self.pe.va(va)
        return va

    def get_utf_str(self, va, off):
        va = self._is_va(va)
        const = self._get_const_addr(va)
        off = const + off * 0x4
        data = self.vba.ana.get_bytes(off, 0x4)
        addr = struct.unpack("<L", data)[0]
        return self.read_str(addr)

    def read_str(self, va, size=0x100):
        # Not the best way to read UTF-like strs but gets the job done
        s = bytearray(self.vba.ana.get_bytes(va, size).partition(b'\x00\x00')[0])
        s.append(0x00)
        # .decode('utf-16le')
        return s

    def _init_bound_entry(self, addr):
        if addr not in self.data:
            self.data[addr] = [sys.maxsize,0]


    def WORD(self, data):
        return struct.unpack('<H', data[0:2])[0]


    def print(self):
        for i in self.data:
            print ('Constants at 0x%08x with lower/upper 0x%08x/0x%08x addr limit.' % (i, self.data[i][0], self.data[i][1]))


    def decode_str(self, s):
        decd = ""
        for i in range(0, len(s)):
            decd = decd + chr(ord(s[i]) - 5)
        return decd

def get_var_info(l,name):
	return [(o,s,d) for (o,s,d) in l if s == name]

def get_data_obj(peldr, vba):
	header = vba.get_header()
	project_data = vba.get_project_data(header)
	obj_table = vba.get_object_table(project_data)
	proj_data2 = vba.get_project_data2(obj_table)

	return Data(peldr, vba, obj_table, proj_data2)


def get_b64_conf(data, t):
	
	b64 = ""

	arr = get_var_info(data['strings'], '$b64data')
	if len(arr) > 0:
		for (o,s,d) in arr:
			if d[0] == 0x1b:
				off = t.WORD(d[1:3])
				s = t.get_utf_str(o,off).decode('utf-16le')
				b64 += s

	return b64




def get_vba_parser():
	pe = pefile.PE(sys.argv[1])
	mem = vb.analyzer.PELoader(pe)
	ana = vb.analyzer.Analyzer(mem)
	return mem, vb.VBAnalyzer(ana)



def get_aes_key(data, t):
	key = ""
	arr = get_var_info(data['strings'], '$main')
	if len(arr) == 1:
		for (o,s,d) in arr:
			if d[0] == 0x1b:
				off = t.WORD(d[1:3])
				key = t.get_utf_str(o,off).decode('utf-16le')
	return key

def get_config(data):
	peldr, vba = get_vba_parser()
	d = get_data_obj(peldr, vba)

	b64_conf = get_b64_conf(data,d)
	s_encr_conf = base64.b64decode(b64_conf)
	key = get_aes_key(data,d)
	
	if key:
		key = d.decode_str(key)
	aes = AESCipher(key)
	decrypted_conf = aes.decrypt(b64_conf)
	conf = zlib.decompress(decrypted_conf, -15)
	print (conf)
	



def main(): 
	rule = yara.compile(filepath='diamondfox.yar')
	match = rule.match(sys.argv[1], callback=get_config, which_callbacks=yara.CALLBACK_MATCHES)





if __name__ == '__main__':
	main()