#!/bin/python2
# -*- coding: cp1252 -*-

##
## Criacao da UI principal
##

import Tkinter
from Tkinter import *
import time
import plot
###############################UI principal#####################################
class Window(Tkinter.Frame):
    """docstring for Window"""
    def __init__(self, parent):

        Tkinter.Frame.__init__(self, parent)
        self.parent = parent

        self.initUI()

    def initUI(self):
        menubar = Menu(self.parent)
        self.parent.config(menu=menubar)

        fileMenu =  Menu(menubar)
        menubar.add_cascade(label="File", underline=0, menu=fileMenu)
        fileMenu.add_command(label="Plot", underline=0, command=plot.Trd_plot(parent))
        fileMenu.add_command(label="Exit", underline=0, command=self.onExit)
#################################FUNCOES########################################

    def onExit(self):
        time.sleep(0.5)
        self.parent.destroy()
