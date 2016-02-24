#!/bin/python2
# -*- coding: cp1252 -*-


#impott para window
import Tkinter
from Tkinter import *
import time

#import para plot
import threading
import pylab
from pylab import *
import matplotlib.pyplot
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2TkAgg
from collections import deque

#impot para leitura
import socket
from struct import *

################################################################################
lista_bler = deque([0]*1000)
lista_media = deque([0]*1000)

contador_harq=0
contador_amostra=1
import random
def delete_item():
    global lista_bler, lista_media
    del lista_bler[len(lista_bler)-1]
    del lista_media[len(lista_media)-1]
################################################################################
##
## Criacao da UI principal
##
################################################################################
###############################UI principal#####################################
################################################################################
class Window(Tkinter.Frame):
    """docstring for Window"""
    def __init__(self, parent):
        global parente

        Tkinter.Frame.__init__(self, parent)
        self.parent = parent
        self.initUI()
        parente = self.parent

    def initUI(self):
        menubar = Menu(self.parent)
        self.parent.config(menu=menubar)

        fileMenu =  Menu(menubar)
        menubar.add_cascade(label="File", underline=0, menu=fileMenu)
        fileMenu.add_command(label="Plot", underline=0, command=self.init_plot)
        fileMenu.add_command(label="Exit", underline=0, command=self.onExit)
#################################FUNCOES########################################

    def onExit(self):
        time.sleep(0.5)
        self.th_plot.stop()
        self.th_leitura.stop()
        self.parent.destroy()

    def init_plot(self):
        self.th_plot = Trd_plot()
        self.th_plot.start()
        self.th_leitura = Trd_leitura()
        self.th_leitura.start()
################################################################################
##
## Criacao do Plot
##
################################################################################
##############################CLASS_THREAD######################################
################################################################################

class Trd_plot(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self.paused = True
        self._running = True
        self.state = threading.Condition()

    def run(self):
        #parente = parent de window
        #lista_bler = deque (lista_bler circular de valores de line)
        global parente, lista_bler, contador_harq, contador_amostra

        figura = pylab.figure(1)
        ax = figura.add_axes([0.1,0.1,0.8,0.8])
        ax.grid(True)
        ax.set_title("Plot anything")
        ax.set_xlabel("time")
        ax.set_ylabel("ampl")
        ax.axis([0,1000,0,100])

        line_bler, = pylab.plot(lista_bler)
        line_media, = pylab.plot(lista_media, 'r')#lista_bler de media

        canvas =  FigureCanvasTkAgg(figura, master=parente)
        canvas.get_tk_widget().pack(side=Tkinter.TOP, fill=Tkinter.BOTH, expand=1)
        canvas.show()

        toolbar = NavigationToolbar2TkAgg(canvas, parente)
        toolbar.update()
        canvas._tkcanvas.pack(side=Tkinter.TOP, fill=Tkinter.BOTH, expand=1)
        ########################################################################
        #                         Geracao do grafico                           #
        ########################################################################
        media = 0
        while True:
            valor_plot_bler = (contador_harq/contador_amostra)*100
            ####################################################################
            soma = 0
            for v in lista_bler:
                soma +=v
            media = (soma)/len(lista_bler)
            ####################################################################

            delete_item()

            lista_bler.appendleft(valor_plot_bler)
            lista_media.appendleft(media)

            print lista_bler
            line_media.set_ydata(lista_media)
            line_bler.set_ydata(lista_bler)
            canvas.draw()
            time.sleep(0.01)

################################################################################
    def stop(self):
        with self.state:
            self._running=False

################################################################################
##
## Leitura socket
##
################################################################################
##############################CLASS_THREAD######################################
################################################################################
class Trd_leitura(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self.paused = True
        self.state  = threading.Condition()

    def run(self):
        global contador_harq, contador_amostra
        ##########  conexao  ###############################################
        host=''
        port=8888
        local=(host, port)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(local)
        ####################################################################
        while True:
            leitor, recebe = udp.recvfrom(65535)
            msg_Id,len_Ven,buff_Length,frame=unpack('>BBHH',leitor[0:6])
            ############################################################
            ######### ----configuracoes de descompacta----- ############
            Sfn=int(Frame) >> 4
            Sf=int(Frame) & 0xF
            if msg_Id is 133:
                contador_amostra +=1
                try:
                    msg_Id,len_Ven,buff_Length,Frame, num_of_harq, rnti, harq_tb1, harq_tb2 = unpack('>BBHHHHBB', leitor)
                    if (harq_tb1 is not 1):
                        contador_harq+=1

                except Exception as e:
                    raise

    def stop(self):
        with self.state:
            self._running=False
