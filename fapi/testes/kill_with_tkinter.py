import Tkinter
from Tkinter import *

import threading
import time

import Classes

class Trd_teste(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self.state = threading.Condition()

        def run(self):
            print 'foi'

        def stop(self):
            with self.state:
                self.stop =True

class Tela(Tkinter.Frame):
    def __init__(self, parent):
        Tkinter.Frame.__init__(self, parent)
        self.parent = parent
        self.initUI()

    def initUI(self):
        frame = Frame(self.parent)
        frame.pack()
        self.btn1 = Button(frame, text = 'inicia thread',width=10, command=lambda:self.thread_init())
        self.btn1.pack()
        self.btn2 = Button(frame, text = 'kill thread',width=10, command=lambda:self.thread_kill())
        self.btn2.pack()

    def thread_init(self):
        inicia_th = Trd_teste()
        inicia_th.start()


    def thread_kill(self):
        pass


def main():
    root = Tkinter.Tk()
    root.wm_title("Janela")
    root.geometry("200x200")
    app = Tela(root)
    root.mainloop()

if __name__ == '__main__':
    main()
