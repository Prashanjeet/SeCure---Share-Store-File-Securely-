import tools
from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
import os


import cv2
from steganography import Steganography
def Algo1(key, fname):
	f = Fernet(key)
	target_file = open('./encrypted/'+ fname + "/raw_data/store_in_me.enc","rb")
	secret_data = ""
	for line in target_file:
		secret_data = secret_data + line
	data = f.decrypt(secret_data)
	target_file.close()
	return data

def Also1_RSA(filename, key1, key2, fname):
	f = MultiFernet([Fernet(key1),Fernet(key2)])
	source_filename = 'encrypted/'+ fname+'/files/' + filename
	target_filename = 'files/' + filename
	file = open(source_filename,'rb')
	target_file = open(target_filename,'wb')
	raw = ""
	for line in file:
		raw = raw + line
	secret_data = f.decrypt(line)
	target_file.write(secret_data)
	file.close()
	target_file.close()

def Also2_TrippleDES(filename, key, nonce, fname):
	aad = "authenticated but unencrypted data"
	chacha = ChaCha20Poly1305(key)
	source_filename = 'encrypted/' + fname+'/files/'+ filename
	target_filename = 'files/' + filename
	file = open(source_filename,'rb')
	target_file = open(target_filename,'wb')
	raw = ""
	for line in file:
		raw = raw + line
	secret_data = chacha.decrypt(nonce, raw, aad)
	target_file.write(secret_data)
	file.close()
	target_file.close()

def Algo3(filename, key, nonce, fname):
	aad = "authenticated but unencrypted data"
	aesgcm = AESGCM(key)
	source_filename = 'encrypted/'+ fname+'/files/' + filename
	target_filename = 'files/' + filename
	file = open(source_filename,'rb')
	target_file = open(target_filename,'wb')
	raw = ""
	for line in file:
		raw = raw + line
	secret_data = aesgcm.decrypt(nonce, raw, aad)
	target_file.write(secret_data)
	file.close()
	target_file.close()

def Algo4(filename, key, nonce, fname):
	aad = "authenticated but unencrypted data"
	aesccm = AESCCM(key)
	source_filename = 'encrypted/' + fname+'/files/'+ filename
	target_filename = 'files/' + filename
	file = open(source_filename,'rb')
	target_file = open(target_filename,'wb')
	raw = ""
	for line in file:
		raw = raw + line
	secret_data = aesccm.decrypt(nonce, raw, aad)
	target_file.write(secret_data)
	file.close()
	target_file.close()

def decrypter(Fname):
	tools.empty_folder('files')
	tools.empty_folder('./key_pem')
	list_directory = tools.list_dir('key')
	filename = './key/' + list_directory[0]
	in_f = filename
	out_f = "./key_pem/" + Fname +".pem"
	in_img = cv2.imread(in_f)
	steg = Steganography(in_img)
	key_1 = steg.decode_binary()

	secret_information = Algo1(key_1, Fname)
	list_information = secret_information.split(':::::')
	key_1_1 = list_information[0]
	key_1_2 = list_information[1]
	key_2 = list_information[2]
	key_3 = list_information[3]
	key_4 = list_information[4]
	nonce12 = list_information[5]
	nonce13 = list_information[6]
	files = sorted(tools.list_dir('./encrypted/' + Fname + '/files'))
	for index in range(0,len(files)):
		if index%4 == 0:
			Also1_RSA(files[index],key_1_1,key_1_2, Fname)
		elif index%4 == 1:
			Also2_TrippleDES(files[index],key_2,nonce12, Fname)
		elif index%4 == 2:
			Algo3(files[index],key_3,nonce12, Fname)
		else:
			Algo4(files[index],key_4,nonce13, Fname)
