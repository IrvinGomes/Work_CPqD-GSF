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
x_linha=3000              ##escala de x(tanto no deque quanto no grafico)
flag=False                ##flag que avisa quando completa o buffer
valor_plot_bler = 0            ##buffer inicial
lista=deque([0]*x_linha)
flag_stop=False
flag_plot=False
cont_harq=1
conta_amostras=1.0
################################################################################
def delete():
  global lista, x_linha
  del lista[len(lista)-1]
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
        helpMenu.add_command(label="About Program of Plot", underline=0, command=self.about)
        menubar.add_cascade(label="Help",underline=0, menu=helpMenu)
################################################################################
    #Criacao da UI2
    def initUI2(self):
        frame=Frame(self.parent)
        frame.pack(side=LEFT)

        self.b1=Button(frame, text='Encontrar UE',width=10)
        self.b2=Button(frame, text='Plotar CQI ',width=10, )
        self.b3=Button(frame, text='Plotar Bler',width=10, command=self.thread_init)
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
            self.th_leitura_bler=threading.Thread(target= self.leitura_bler)
            self.th_leitura_bler.start()
            self.th_cria_graf = threading.Thread(target = self.cria_grafi)
            self.th_cria_graf.start()
            flag_plot = True
        else:
            pass

    def onExit(self):
        global flag_stop
        flag_stop = True
        time.sleep(1)
        self.parent.destroy()
        self.parent.quit()

    def about(self):
        top = Toplevel()
        top.geometry("400x300")
        top.title("About")

        msg_about=Label(top, text="\nEste programa foi idealizado pela equipe de\n"
                        "Software da Gerencia de Redes sem Fio do CPqD\n"
                        "(Centro de Pesquisa e Desenvolvimento em Telecom)\n"
                        "com o intuito de auxiliar e examinar os sinais\n"
                        "e mensagens entre UE e eNodeB",width=50).pack()
        msg_devol=Label(top, text="\nDesenvolvedor: Irvin R. Gomes").pack()
        #btn = Button(top,text = "   OK   ", command = top.destroy())
        #btn.pack()
    ########################################################################
    ########################################################################

    ########################################################################
    #		             conecta e manda para plota                        #
    ########################################################################
    def leitura_bler(self):
        global valor_plot_bler, lista, flag, flag_stop, conta_amostras, cont_harq
        ##########  conexao  ###############################################
        host=''
        port=8888
        local=(host, port)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(local)
        ####################################################################
        ######### ----- configuracoes de leitura_bler_bler  ----- ##########

        while flag_stop == False:
            leitor, recebe = udp.recvfrom(65535)
            msg_Id,len_Ven,buff_Length, Frame=unpack('>BBHH', leitor[0:6])
            if msg_Id is 133:
                conta_amostras +=1
                try:
                    msg_Id,len_Ven,buff_Length,Frame, num_of_harq, rnti, harq_tb1, harq_tb2 = unpack('>BBHHHHBB', leitor)
                    ############################################################
                    ######### ----configuracoes de descompacta----- ############
                    Sfn=int(Frame) >> 4
                    Sf=int(Frame) & 0xF

                    if (harq_tb1 is not 1):
                        cont_harq +=1

                except Exception as e:
                #    print ":".join("{:02x}".format(ord(c)) for c in leitor)
                    raise
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
        ax.set_xlabel("Tempo (em 0.5 segundos)")
        ax.set_ylabel("Amplitude(em porcentagem)")
        ax.axis([0,1000,0,100])


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
            valor_plot_bler = (cont_harq/conta_amostras)*100

            #texto_bler = 'Valor de bler:'
            #ax.text(65, 95, '')
            #ax.text(85, 95, '')
            #ax.text(650, 95, texto_bler)
            #ax.text(850, 95, valor_plot_bler)

            #texto_amostras = 'Amostras / Harq:'
            #ax.text(60,90, texto_amostras)
            #ax.text(85,90, conta_amostras)
            #ax.text(90,90.1, '/')
            #ax.text(92,90, cont_harq)

            print 'Amostras: ', conta_amostras, ' Harq is not 1: ', cont_harq, ' BLER: ', valor_plot_bler
            delete()
            lista.appendleft(valor_plot_bler)
            line.set_ydata(lista)

            canvas.draw()
            conta_amostras = 1.0
            cont_harq = 0
            time.sleep(0.05)

################################################################################
################################################################################

################################################################################
#                                    Main                                      #
################################################################################
def main():

    root=Tkinter.Tk()
    root.wm_title("FAPI Log Analyzer")
    app=Packing(root)
    root.geometry("700x600")
    root.mainloop()

if __name__ == '__main__':
    main()
