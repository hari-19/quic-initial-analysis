from selenium import webdriver
import time


def open_browser(url, timeout):
    driver = webdriver.Firefox()
    driver.get(url)
    # time.sleep(timeout)
    driver.close()
    driver.quit()

i = 0
urls = ["https://www.uber.com/", "https://www.waze.com/", "https://www.justwatch.com", "https://www.amazon.com", "https://www.facebook.com"]

while True:
    i+=1
    url = urls[i%len(urls)]
    open_browser(url, 10)
