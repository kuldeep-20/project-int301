import pyshark
import socket

# obtaining the ip address of the vulnerable website
ip_address = socket.gethostbyname("testhtml5.vulnweb.com")

# the port on which the vulnerable website interacts with the interface
tcp_port = "80"

# display (wireshark) filter to apply on the Live Capture
http_filter = "http and tcp.port == {port} and ip.addr == {ip}".format(port = tcp_port, ip = ip_address)

# method to capture http packets with the display filter initialized above
def intercept_http_packets(network_interface):
    capture = pyshark.LiveCapture(interface=network_interface, display_filter=http_filter)
    for packet in capture.sniff_continuously():
        filter_layer_from_packet(packet)

# method to filter the packets having the login form data
def filter_layer_from_packet(packet):
    for layer in packet.layers:
        if layer.layer_name == "urlencoded-form":
            extract_login_credentials_from_output_file(packet)
