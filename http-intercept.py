import pyshark
import socket

# obtaining the ip address of the vulnerable website
ip_address = socket.gethostbyname("testhtml5.vulnweb.com")

# the port on which the vulnerable website interacts with the interface
tcp_port = "80"

# display (wireshark) filter to apply on the Live Capture
http_filter = "http and tcp.port == {port} and ip.addr == {ip}".format(port = tcp_port, ip = ip_address)
