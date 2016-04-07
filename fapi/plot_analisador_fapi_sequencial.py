#!/usr/bin/python
#-*- coding: UTF-8 -*-

from subprocess import call
from collections import deque
from struct import *
import matplotlib.pyplot as plt
import socket
import os
import time
import numpy as np
import threading

valor_Sf=3
i=0
################################################################################
#						Plota grafico
################################################################################
def plota_graf():
    a1 = deque([0]*100)
    ax = plt.axes(xlim=(0, 100), ylim=(0, 15))
    #d = leitura(loc)

    line, = plt.plot(a1)
    plt.ion()
    plt.ylim([0,15])
    plt.show()
    for i in range (1,1000):
        a1.appendleft(valor_Sf)
        datatoplot = a1.pop()
        line.set_ydata(a1)
        plt.draw()
        #time.sleep(0.1)
        #plt.pause(0.01)
################################################################################
#					conecta e manda para plota
################################################################################
def leitura(local):
    global valor_Sf, i
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(local)
#    while True:
    for i in range (1,100000):
        #leitor, recebe = udp.recvfrom(1)
        #leitor=unpack('>B', leitor)[0:1]
        try:
            leitor, recebe = udp.recvfrom(12)
            print len(leitor)
            leitor=unpack('>BBHHHL', leitor)[0:6]
        except Exception as e:
            """leitor, recebe = udp.recvfrom(8)
            print len(leitor)
            leitor=unpack('>BBHHH', leitor)[0:5]
            print leitor"""
            pass



        if (leitor[0] == 139):

            print len(leitor)

            Sfn=int(leitor[3]) >> 4;
            Sf=int(leitor[3]) & 0xF;
            print '###########################'
            print 'LTE-PHY Header'
            print '             Msg Id:', leitor[0]
            print '   Len Ven Specific:', leitor[1]
            print '         BuffLength:', leitor[2]
            print ''
            print 'Rx CQI INDICATION'
            print 'System Frame Number:', Sfn
            print '                 Sf:', Sf
            print '         Num of CQI:', leitor[4]
            print ''
            print 'CQI PDU Indication'
            print '             Hundle:', leitor[5]
            #print '               RNTI:', leitor[6]
            #print '             Length:', leitor[7]
            #print '        Data Offset:', leitor[8]
            #print '    Timming advance:', leitor[9]
            #print '             UL CQI:', leitor[10]
            #print '                 RI:', leitor[11]
            valor_Sf=Sf
            #i+=1
            #yield Sf"""
################################################################################
#					main
################################################################################
def main():
    host=''
    port=8888
    local=(host, port)

    th1=threading.Thread(target=plota_graf)
    #th1.start()
    th2=threading.Thread(target=leitura, args=(local,))
    th2.start()
    #th1.join()
    #plota_graf(local)

if __name__ == '__main__':
    main()
