import socket
from struct import *

host =''
port = 8888
local = (host,port)

udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
udp.bind(local)

while True:
  leitor, recebe = udp.recvfrom(65000)

  msg_Id, len_Ven, buff_Length, frame = unpack('>BBHH', leitor[0:6])

  print msg_Id, len_Ven, buff_Length

if msg_Id is 0x87:

  num_of_pdu = unpack('>H', leitor[7:8])

  print num_of_pdu
