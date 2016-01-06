import time
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
    motivo="Estágio / Bolsa"

    http="http://sistemas.ft.unicamp.br/onibus/"
    driver.get(http)

    try:
        box1 = driver.wait.until(EC.presence_of_element_located((By.NAME, "user")))
        box1.send_keys(login)
        box2 = driver.wait.until(EC.presence_of_element_located((By.NAME, "password")))
        box2.send_keys(senha)
        box2.send_keys(Keys.RETURN)

        ##entrou na pagina
        box3 = driver.wait.until(EC.presence_of_element_located((By.NAME, "Solicitar")))
        box3.click()

        #box4 = driver.wait.until(EC.presence_of_element_located((By.NAME, "entry.1000005")))
        #box4.send_keys(motivo)
        #box5 = driver.wait.until(EC.presence_of_element_located((By.NAME, "entry.1000008")))
        #box5.send_keys(data)
        #box6 = driver.wait.until(EC.presence_of_element_located((By.NAME, "entry.1000006")))
        #box6.click()
        #box7 = driver.wait.until(EC.presence_of_element_located((By.NAME, "entry.1000007")))
        #box7.click()
        #box8 = driver.wait.until(EC.presence_of_element_located((By.NAME, "submit")))
        #box8.click()
    except TimeoutException:
        print("Nao foi")


def main():
    for ano in range(2015,2016):
        for mes in range(12,13):
            for dia in range(18,32):
                data=str(dia)+"/"+str(mes)+"/"+str(ano)
                print('',data)
                driver = init_driver()
                lookup(driver, data)
                time.sleep(0.5)
                driver.quit()


if __name__ == "__main__":
    main()
