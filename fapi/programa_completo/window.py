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
lista = deque([0*1000])
import random
def delete_item():
    global lista
    del lista[len(lista)-1]
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
        global parente, lista

        self.parent = parente

        figura = pylab.figure(1)
        ax = figura.add_axes([0.1,0.1,0.8,0.8])
        ax.grid(True)
        ax.set_title("Plot anything")
        ax.set_xlabel("time")
        ax.set_ylabel("ampl")
        ax.axis([0,1000,0,100])

        line, = pylab.plot(lista)

        canvas =  FigureCanvasTkAgg(figura, master=self.parent)
        canvas.get_tk_widget().pack(side=Tkinter.TOP, fill=Tkinter.BOTH, expand=1)
        canvas.show()

        toolbar = NavigationToolbar2TkAgg(canvas, self.parent)
        toolbar.update()
        canvas._tkcanvas.pack(side=Tkinter.TOP, fill=Tkinter.BOTH, expand=1)
        ########################################################################
        #                         Geracao do grafico                           #
        ########################################################################
        vai = 1
        while vai is 1:
            num = random.randint(0,100)
            delete_item()

            lista.appendleft(num)

            line.set_ydata(lista)
            print lista
            canvas.draw()
            time.sleep(1)

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
        ##########  conexao  ###############################################
        host=''
        port=8888
        local=(host, port)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(local)
        ####################################################################
        leitor, recebe = udp.recvfrom(65535)
        msg_Id,len_Ven,buff_Length,frame=unpack('>BBHH',leitor[0:6])

    def stop(self):
        with self.state:
            self._running=False
