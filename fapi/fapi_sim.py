import socket
import time
import struct
import random

def conect(local):
    conect_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:

        msg_Id          = 0x8b          # B
        len_Ven         = 0x00          # B
        buff_Length     = 0x0015        # H

        sub_frame       = 0             # ambos sao 1
        sys_frame_n     = 0             # H

        num_of_cqi      = 0x0001        # H

        handle          = 0x00000001    # Q
        rnti            = 0x0034        # B
        length          = 0x0001        # B
        data_offset     = 0x0010        # B
        timming_advance = 0x001f        # B
        ul_cqi          = 0
        ri              = 0x00          # H


        for sys in range(0,1024):
            sys_frame_n = sys

            for sub in range(0,10):
                sub_frame=sub
                frame = (sub_frame & 0x0F) | (sys_frame_n << 4)

                if sub%2 == 0:
                    ul_cqi          = random.randint(150,160)#0x8b          # B
                    print ul_cqi
                    mensagem = struct.pack('>BBHHHQBBBBBH', msg_Id,len_Ven,buff_Length, frame, num_of_cqi,
                                            handle, rnti,length, data_offset, timming_advance, ul_cqi, ri)

                    conect_socket.sendto(mensagem, local)
                time.sleep(0.0001)

def main():
    mensagem=''
    port = 8888
    ip = "172.16.130.76"
    local=((ip, port))

    conect(local)

if __name__ == '__main__':
    main()
