import socket
import os
HOST="192.168.56.1"

def main():
    if os.name == 'nt':
        socket_protocal = socket.IPPROTP_IP
    else:
        socket_protocal = socket.IPPROTO_ICMP

        sniffer = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket_protocal)
        sniffer.blind(HOST,0)
        sniffer.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
        #only for windows

        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)
        print(sniffer.recvfrom(65565))

        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL,socket.RCVALL_OFF)

if __name__ == 'main':
    main()

