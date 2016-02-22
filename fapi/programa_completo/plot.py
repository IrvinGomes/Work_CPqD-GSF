#!/bin/python2
# -*- coding: cp1252 -*-

##
## geracao de plot
##
import threading

class Trd_plot(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self.paused = True
        self.state = threading.Condition()

    def run(self):
        figura = pylab.figure(1)
        ax = figura.add_axes([0.1,0.1,0.8,0.8])
        ax.grid(True)
        ax.set_title("Testando")
        ax.axis([0,1000,0,100])
