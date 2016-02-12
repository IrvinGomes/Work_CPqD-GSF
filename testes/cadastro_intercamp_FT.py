#!/bin/python
import time
from datetime import datetime
now = datetime.now()

import datetime

from selenium.webdriver.common.keys import Keys
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException


def init_driver():
    driver = webdriver.Firefox()
    driver.wait = WebDriverWait(driver, 5)
    return driver


def lookup(driver, data):
    login="i081641"
    senha="irg094001"
    ra="081641"
    nome="Irvin Gomes"
    email="irvin.alemao@gmail.com"
    motivo="es"

    http="http://sistemas.ft.unicamp.br/onibus/"
    driver.get(http)

    try:
        box1 = driver.wait.until(EC.presence_of_element_located((By.NAME, "user")))
        box1.send_keys(login)
        box2 = driver.wait.until(EC.presence_of_element_located((By.NAME, "password")))
        box2.send_keys(senha)
        box2.send_keys(Keys.RETURN)

        ##entrou na pagina
        box3 = driver.wait.until(EC.presence_of_element_located((By.NAME, "motivo")))
        box3.send_keys(motivo)
        box3.send_keys(Keys.TAB)
        box4 = driver.wait.until(EC.presence_of_element_located((By.NAME, "data_uso")))
        box4.send_keys(data)
        box4.send_keys(Keys.TAB, Keys.TAB, Keys.TAB, Keys.ENTER)

    except TimeoutException:
        print("Nao foi")


def main():
    Diasemana = ('segunda feira','terceira feira','quarta feira', 'quinta feira','sexta feira','sabado','domingo')
    agora = datetime.date.today()
    data = datetime.date.weekday(agora)
    result=agora.strftime('%d/%m/%Y')
########################################################################################################################
#transforma data (nao precisa, isso é so para teste)
    #data = datetime.date.weekday(agora - datetime.timedelta(days=2))
    #agora = agora - datetime.timedelta(days=2)
    #print(agora.strftime('%d/%m/%Y'))
    #print(Diasemana[data])
    #print('')
########################################################################################################################

    data2 = datetime.date.weekday(agora + datetime.timedelta(days=4))
    agora2 = agora + datetime.timedelta(days=4)
    print(agora2.strftime('%d/%m/%Y'))
    print(Diasemana[data2])
    print('')

    if data2 is 5:
        data = datetime.date.weekday(agora + datetime.timedelta(days=6))
        agora = agora + datetime.timedelta(days=6)
        result=agora.strftime('%d/%m/%Y')
        #print(agora.strftime('%d/%m/%Y'))
        #print(Diasemana[data])
        #print('')
        #print('vai mandar', result)
        #print('')
    if data2 is 6:
        data = datetime.date.weekday(agora + datetime.timedelta(days=5))
        agora = agora + datetime.timedelta(days=5)
        result=agora.strftime('%d/%m/%Y')
        #print(agora.strftime('%d/%m/%Y'))
        #print(Diasemana[data])
        #print('')
        #print('vai mandar', result)
        #print('')

    print('vai mandar', result)
    driver = init_driver()
    lookup(driver, result)
    time.sleep(0.5)
    driver.quit()


if __name__ == "__main__":
    main()
