#!/usr/bin/env python
import select, socket, sys, getopt, time, datetime, os

def listen(ip, port, file):
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind((ip, port))
	sock.setblocking(1)

	f = open(file,"a")

	while True:
	    data, addr = sock.recvfrom(1024)
	    f.write(datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')) 
	    f.write(" ")
	    f.write(addr[0])
	    f.write(" ")
	    f.write(data) 
	    f.write("\n")
	    f.flush()

def main(argv):
	ip = ''
	port = 5055
	file = ''
	try:
		opts, args = getopt.getopt(argv,"l:p:f:")
	except getopt.GetoptError:
		print 'sa2dnsbl.py -l <ip> -p <port> -f <logfile>'
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print 'sa2dnsbl.py -l <ip> -p <port> -f <logfile>'
			sys.exit()
		elif opt in ("-l"):
			ip = arg
		elif opt in ("-p"):
			port = int(arg)
		elif opt in ("-f"):
			file = arg
	listen(ip, port, file)

if __name__ == "__main__":
	main(sys.argv[1:])

