import socket
import re

#client side
client = socket.socket()
client.connect(("192.168.200.52",19002))

pattern = "You open the door"

while True:
	rec_msg = client.recv(1024)
	if re.match(pattern,rec_msg.decode('uft-8'):
		break
	else:
		print(rec_msg.decode('utf-8'))
		client.send(input(">> ").encode('utf-8'))
		time.sleep(0.25)

print(rec_msg.decode('utf-8'))

#server side
