import tools
import os
from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from steganography import Steganography
import cv2
import os

def Algo1(data, key, fname):
	f = Fernet(key)
	target_file = open('./encrypted/' + fname + "/raw_data/store_in_me.enc","wb")
	secret_data = f.encrypt(data)
	target_file.write(secret_data)
	target_file.close()

def Algo1_extented(filename, key1, key2, fname):
	f = MultiFernet([Fernet(key1),Fernet(key2)])
	source_filename = 'files/' + filename
	target_filename = './encrypted/' +  fname + '/files/' + filename
	file = open(source_filename,'rb')
	target_file = open(target_filename,'wb') # Error in this line
	raw = ""
	for line in file:
		raw = raw + line
	secret_data = f.encrypt(raw)
	target_file.write(secret_data)
	file.close()
	target_file.close()

def Algo2(filename, key, nonce, fname):
	aad = "authenticated but unencrypted data"
	chacha = ChaCha20Poly1305(key)
	source_filename = 'files/' + filename
	target_filename = './encrypted/' +  fname + '/files/' + filename
	file = open(source_filename,'rb')
	target_file = open(target_filename,'wb')
	raw = ""
	for line in file:
		raw = raw + line
	secret_data = chacha.encrypt(nonce, raw, aad)
	target_file.write(secret_data)
	file.close()
	target_file.close()

def Algo3(filename, key, nonce, fname):
	aad = "authenticated but unencrypted data"
	aesgcm = AESGCM(key)
	source_filename = 'files/' + filename
	target_filename = './encrypted/' + fname + '/files/' + filename
	file = open(source_filename,'rb')
	target_file = open(target_filename,'wb')
	raw = ""
	for line in file:
		raw = raw + line
	secret_data = aesgcm.encrypt(nonce, raw, aad)
	target_file.write(secret_data)
	file.close()
	target_file.close()

def Algo4(filename, key, nonce, fname):
	aad = "authenticated but unencrypted data"
	aesccm = AESCCM(key)
	source_filename = 'files/' + filename
	target_filename = './encrypted/' +  fname + '/files/' + filename
	file = open(source_filename,'rb')
	target_file = open(target_filename,'wb')
	raw = ""
	for line in file:
		raw = raw + line
	secret_data = aesccm.encrypt(nonce, raw, aad)
	target_file.write(secret_data)
	file.close()
	target_file.close()

def encrypter(fname):
	tools.empty_folder('./encrypted/' + fname + '/files/' )
	tools.empty_folder('./key/')
	key_1 = Fernet.generate_key()
	key_1_1 = Fernet.generate_key()
	key_1_2 = Fernet.generate_key()
	key_2 = ChaCha20Poly1305.generate_key()
	key_3 = AESGCM.generate_key(bit_length=128)
	key_4 = AESCCM.generate_key(bit_length=128)
	nonce13 = os.urandom(13)
	nonce12 = os.urandom(12)
	files = sorted(tools.list_dir('files'))
	for index in range(0,len(files)):
		if index%4 == 0:
			Algo1_extented(files[index],key_1_1,key_1_2, fname)
		elif index%4 == 1:
			Algo2(files[index],key_2,nonce12, fname)
		elif index%4 == 2:
			Algo3(files[index],key_3,nonce12, fname)
		else:
			Algo4(files[index],key_4,nonce13, fname)
	secret_information = (key_1_1)+":::::"+(key_1_2)+":::::"+(key_2)+":::::"+(key_3)+":::::"+(key_4)+":::::"+(nonce12)+":::::"+(nonce13)
	Algo1(secret_information,key_1, fname)

	# Static path to the image file for Steganography
	in_f = "./static/png.png"
	#out_f = './encrypted/' + fname + '/key/'  + fname + '.png'
	out_f = './key/'  + fname + '.png'
	in_img = cv2.imread(in_f)
	steg = Steganography(in_img)

	res = steg.encode_binary(key_1)
	cv2.imwrite(out_f, res)

	tools.empty_folder('files')
