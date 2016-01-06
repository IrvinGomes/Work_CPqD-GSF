############## client.py#################
#!/usr/bin/python
import socket
import random
import time
import threading
#ip = raw_input('digite o ip de conexao: ')
##################################################################
#                funcao para conectar e enviar                   #
##################################################################
def conect():
    ip = "143.106.243.60"
    addr = ('143.106.243.60',80)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(addr)
    while True:
        mensagem = ''
        client_socket.sendall(mensagem)



##################################################################
#                           funcao main                          #
##################################################################
def main():
    th1=threading.Thread(target= conect)
    th1.start()

if __name__ == '__main__':
    main()
