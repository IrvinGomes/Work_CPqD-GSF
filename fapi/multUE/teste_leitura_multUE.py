import socket
from struct import *

# unpack:
# B = 1
# H = 2

host =''
port = 8888
local = (host,port)

udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
udp.bind(local)

while True:
  leitor, recebe = udp.recvfrom(65000)

  msg_Id, len_Ven, buff_Length, frame = unpack('>BBHH', leitor[0:6])

  if msg_Id is 135: #133 -> harq
    num_of_pdu = unpack('>H', leitor[6:8])
    print num_of_pdu
    #print msg_Id, len_Ven, buff_Length

    #msg_Id, len_Ven, buff_Length, frame_bler, num_of_harq, rnti,\
    #harq_tb1, harq_tb2 = unpack('>BBHHHHBB', leitor)

    #rnti = unpack('>H', leitor[8:10])

    #harq_tb1 = unpack('>B',leitor[10:11])
    #harq_tb2 = unpack('>B',leitor[11:12])
    #print rnti, harq_tb1, harq_tb2
