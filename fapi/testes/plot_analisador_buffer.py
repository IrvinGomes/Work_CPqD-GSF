#!/usr/bin/python2
#-*- coding: UTF-8 -*-

from subprocess import call
from collections import deque
from struct import *

import matplotlib.pyplot as plt
import socket
import threading
import time

x=500                   ##escala de x(tanto no deque quanto no grafico)
flag=True                ##flag que avisa quando completa o buffer
valor_plot = range(0,250)  ##buffer inicial

lista=deque([0]*x)
################################################################################
#                          deleta os primeiros da lista                        #
################################################################################
def delete():
  global lista, x
  for i in range(0,250):
    del lista[x-(i+1)]

################################################################################
#                          conecta no socket desejado                          #
################################################################################
def conecta(endereco):
  ######### -----  configuracoes de concta  ----- #########
  udp=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  udp.bind(endereco)
  return udp

################################################################################
#                          thread da plotagem do grafico                        #
################################################################################
def plot_graf():
    global lista, flag, x
    contador = 0

    ax=plt.axes(xlim=(0,x),ylim=(-63,64))
    line, = plt.plot(lista)
    plt.grid(True)
    plt.title('Plot UL CQI')
    plt.ylabel('Value of ul_cqi')
    plt.ion()
    plt.show()
    ########################################################
    while contador<=1000:
        delete()
        lista.extendleft(valor_plot)
        print lista
        ##---desenha a linha atualizada---##
        line.set_ydata(lista)
        plt.draw()
        contador+=1


################################################################################
#					conecta e manda para plot
################################################################################
def leitura(local):
    global valor_plot, lista, flag
    udp=conecta(local)
    cont = 0
    #########################################################
    ######### ----- configuracoes de leitura  ----- #########
    while cont<=1000:
        contador=0
        while contador<=249:
            leitor,recebe = udp.recvfrom(32)

            msg_Id,len_Ven,buff_Length,sub_Frame,num_of_cqi, handle, rnti, length, data_offset, timming_advance, ul_cqi, ri =unpack('>BBHHHQBBBBBH', leitor)
            #########################################################
            ######### ----configuracoes de descompacta----- #########
            if (msg_Id==139):
                Sfn=int(sub_Frame) >> 4
                Sf=int(sub_Frame) & 0xF
                valor_plot[contador]=((ul_cqi - 128)/2)

                contador+=1
                if (contador==250):
                    cont+=1
                    flag=True
                else:
                    flag=False
################################################################################
#					main
################################################################################
def main():
	host=''
	port=8888
	local=(host, port)

	th1=threading.Thread(target=plot_graf)
	th2=threading.Thread(target=leitura, args=(local,))
	th1.start()
	th2.start()

if __name__ == '__main__':
	main()
