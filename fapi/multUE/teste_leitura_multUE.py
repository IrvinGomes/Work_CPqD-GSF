import socket
from struct import *

host =''
port = 8888
local = (host,port)

udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
udp.bind(local)

while True:
  leitor, recebe = udp.recvfrom(65000)

  msg_Id, len_Ven, buff_Length = unpack('>BBH', leitor[0:4])

  print msg_Id, len_Ven, buff_Length
