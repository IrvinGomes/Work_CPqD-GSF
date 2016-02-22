#!/bin/python2
# -*- coding: cp1252 -*-

##
## principal para a criacao do fapi Analyzer de modo completo
##

import Tkinter
import window
import plot

def main():

    root = Tkinter.Tk()
    root.wm_title("Teste")

    app = window.Window(root)

    root.geometry("700x600")
    root.mainloop()

if __name__ == '__main__':
    main()
