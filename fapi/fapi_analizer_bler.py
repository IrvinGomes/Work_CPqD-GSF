#!/bin/python2
# -*- coding: cp1252 -*-

import pylab
from pylab import *
import Tkinter
from Tkinter import *
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2TkAgg

import matplotlib.pyplot as plt
import time
from collections import deque
import random

from struct import *
import socket

import threading
################################################################################
################################################################################
################################################################################
x=3000                   ##escala de x(tanto no deque quanto no grafico)
flag=False                ##flag que avisa quando completa o buffer
valor_plot = 0  ##buffer inicial
lista=deque([0]*x)
flag_stop=False
flag_plot=False
cont_harq=0
conta_amostras=0.0
################################################################################
def delete():
  global lista, x
  del lista[len(lista)-1]
################################################################################
################################################################################
################################################################################
########################################################################
#		             conecta e manda para plota                        #
########################################################################
def leitura():
    global valor_plot, lista, flag, flag_stop, conta_amostras, cont_harq
    ##########  conexao  ###############################################
    host=''
    port=8888
    local=(host, port)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(local)
    ####################################################################
    ############## ----- configuracoes de leitura  ----- ###############
    while flag_stop == False:
        leitor, recebe = udp.recvfrom(65535)
        msg_Id,len_Ven,buff_Length, Frame=unpack('>BBHH', leitor[0:6])
        conta_amostras +=1
        if msg_Id is 133:
            try:
                msg_Id,len_Ven,buff_Length,Frame, num_of_harq, rnti, harq_tb1, harq_tb2 = unpack('>BBHHHHBB', leitor)
                ############################################################
                ######### ----configuracoes de descompacta----- ############
                Sfn=int(Frame) >> 4
                Sf=int(Frame) & 0xF

                if (harq_tb1 is not 1):
                    cont_harq +=1

            except Exception as e:
                print ":".join("{:02x}".format(ord(c)) for c in leitor)
                raise

################################################################################
################################################################################
################################################################################
#                           Criacao da Classe                                  #
################################################################################
class Packing(Tkinter.Frame):
    """docstring for Packing"""

    def __init__(self, parent):

        Tkinter.Frame.__init__(self, parent)
        self.parent = parent

        self.initUI()
        self.initUI2()
################################################################################
################################################################################
################################################################################
#                               Criacao da UI                                  #
################################################################################
    def initUI(self):

        menubar=Menu(self.parent)
        self.parent.config(menu=menubar)

        fileMenu=Menu(menubar)
        helpMenu=Menu(menubar)
        editMenu=Menu(menubar)
        viewMenu=Menu(menubar)
        findMenu=Menu(menubar)
        packagesMenu=Menu(menubar)
        ########################################################################
        menubar.add_cascade(label="File",underline=0, menu=fileMenu)
        #fileMenu.add_command(label="Encontrar UE", underline=10)
        #fileMenu.add_separator()
        fileMenu.add_command(label="Plotar", underline=0, command=self.thread_init)
        fileMenu.add_separator()
        #fileMenu.add_command(label="Salvar", underline=0)
        #fileMenu.add_command(label="Salvar como", underline=1)
        #fileMenu.add_separator()
        fileMenu.add_command(label="Exit", underline=0, command=self.onExit)
        ########################################################################
        submenu=Menu(fileMenu)
        #menubar.add_cascade(label="Edit",underline=0,menu=editMenu)
        #editMenu.add_cascade(label="Adicionar UE's", menu=submenu, underline=0)
        #submenu.add_command(label="UE")
        ########################################################################
        #viewMenu.add_command(label="Vazio")
        #menubar.add_cascade(label="View",underline=0,menu=viewMenu)
        ########################################################################
        #findMenu.add_command(label="Vazio")
        #menubar.add_cascade(label="Find",underline=0,menu=findMenu)
        ########################################################################
        #packagesMenu.add_command(label="Vazio")
        #menubar.add_cascade(label="Packages",underline=0,menu=packagesMenu)
        ########################################################################
        helpMenu.add_command(label="About Program of Plot", underline=0)
        menubar.add_cascade(label="Help",underline=0, menu=helpMenu)
################################################################################
    #Criacao da UI2
    def initUI2(self):
        frame=Frame(self.parent)
        frame.pack(side=LEFT)

        self.b1=Button(frame, text='Encontrar UE',width=10)
        self.b2=Button(frame, text='Adicionar UE ',width=10, )
        self.b3=Button(frame, text='Plotar Grafico',width=10, command=self.thread_init)
        self.b4=Button(frame, text='Exit',width=10, command=self.onExit)

        #self.b1.pack()
        #self.b2.pack()
        self.b3.pack()
        self.b4.pack()
################################################################################
    #funcoes para os botoes
    def thread_init(self):
        global flag_plot
        if flag_plot == False:
            self.th = threading.Thread(target = self.cria_grafi)
            self.th.start()
            flag_plot = True
        else:
            pass

    def onExit(self):
        global flag_stop
        flag_stop = True
        #print flag_stop
        time.sleep(1)
        self.parent.destroy()
        self.parent.quit()
################################################################################
################################################################################

################################################################################
#                           Criacao  do grafico                                #
################################################################################
    def cria_grafi(self):
        global lista, flag, x, flag_stop, cont_harq, conta_amostras
        ########################################################################
        #                     Criacao do Grafico e Tollbar                     #
        ########################################################################
        fig = pylab.figure(1)
        ax = fig.add_axes([0.1,0.1,0.8,0.8])
        ax.grid(True)
        ax.set_title("RealTime plot FAPI - BLER INDICATION")
        ax.set_xlabel("Time em 0.5 segundos")
        ax.set_ylabel("Amplitude(Porcentagem de perda)")
        ax.axis([0,100,0,100])
        line, = pylab.plot(lista)

        canvas = FigureCanvasTkAgg(fig, master=self.parent)
        canvas.get_tk_widget().pack(side=Tkinter.TOP, fill=Tkinter.BOTH, expand=1)
        canvas.show()
        toolbar = NavigationToolbar2TkAgg( canvas, self.parent )
        toolbar.update()
        canvas._tkcanvas.pack(side=Tkinter.TOP, fill=Tkinter.BOTH, expand=1) 
        ########################################################################
        #                         Geracao do grafico                           #
        ########################################################################
        while flag_stop == False:
            valor_plot = 100-((cont_harq/conta_amostras)*100)
            delete()
            lista.appendleft(valor_plot)
            line.set_ydata(lista)
            canvas.draw()
            conta_amostras = 0.0
            cont_harq = 0
            time.sleep(0.5)
################################################################################
################################################################################

################################################################################
#                                    Main                                      #
################################################################################
def main():
    th_leitura=threading.Thread(target=leitura)
    th_leitura.start()
    root=Tkinter.Tk()
    root.wm_title("FAPI Log Analyzer")
    app=Packing(root)
    root.geometry("700x600")
    root.mainloop()

if __name__ == '__main__':
    main()
