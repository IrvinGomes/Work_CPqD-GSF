import socket
import time
import struct

def conect(local):
    conect_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:

        msg_Id = 0x82
        len_Ven = 0x00
        buff_Length = 4
        sub_frame = 0
        sys_frame_n = 0

        for sys in range(0,1024):
            sys_frame_n = sys

            for sub in range(0,10):
                sub_frame=sub
                frame = (sub_frame & 0x0F) | (sys_frame_n << 4)
                mensagem = struct.pack('>BBHH', msg_Id,len_Ven,buff_Length, frame)
                conect_socket.sendto(mensagem, local)
                time.sleep(0.001)

def main():
    mensagem=''
    port = 8888
    ip = "10.202.35.138"
    local=((ip, port))

    conect(local)

if __name__ == '__main__':
    main()
