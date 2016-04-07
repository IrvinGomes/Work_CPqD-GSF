import pylab
from pylab import *
from collections import deque
import socket
from struct import *
import time
import threading

conta_amostras = 1.0
conta_bler = 0

def leitura():
  global conta_bler, conta_amostras

  host=''
  port= 8888
  local =(host, port)
  udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  udp.bind(local)

  while True:
    leitor, recebe = udp.recvfrom(65535)
    msg_Id,len_Ven,buff_Length, Frame=unpack('>BBHH', leitor[0:6])

    conta_amostras +=1

    if msg_Id is 133:
      try:
        msg_Id,len_Ven,buff_Length,Frame, num_of_harq, rnti, harq_tb1, harq_tb2 = unpack('>BBHHHHBB', leitor)
        conta_bler += 1

      except Exception as e:
        raise

def printa():
  global conta_bler,conta_amostras
  while True:
    divisao = (conta_bler/conta_amostras)*100
    porcentagem = (100 - divisao)
    print porcentagem
    conta_amostras = 0.0
    conta_bler = 0
    time.sleep(1)

th1=threading.Thread(target=printa)
th2=threading.Thread(target=leitura)

th2.start()
th1.start()
