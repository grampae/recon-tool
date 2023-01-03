#!/usr/bin/python3
from selenium import webdriver
from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.firefox.options import Options
from webdriver_manager.firefox import GeckoDriverManager
from pathlib import Path
from urllib.parse import urlparse
from Wappalyzer import Wappalyzer, WebPage
from humanize import naturalsize
from concurrent.futures import ThreadPoolExecutor, as_completed
import geckodriver_autoinstaller
import requests
import jinja2
import urllib3
import argparse
import sys
import concurrent.futures
import random
import string
import signal
import warnings
import time
#from tqdm import tqdm
from rich.progress import Progress

#handle argument parsing
parser = argparse.ArgumentParser(description="Screenshots r us", formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-t", dest="single", required=False, help="Single target, ex: http(s)://target.com")
parser.add_argument("-l", dest="urlst", required=False, type=argparse.FileType("r", encoding="UTF-8"), help="List of urls")
parser.add_argument("-d", dest="brlst", required=False, type=argparse.FileType("r", encoding="UTF-8"), help="Enable dir brute force with list")
parser.add_argument("-p", dest="project", required=True, help="Project name")
args = parser.parse_args()
if len(sys.argv)==1:
    parser.print_help(sys.stderr)
    sys.exit(1)
project = args.project
target = args.single
urlst = args.urlst
brlst = args.brlst
if urlst:
	urlist = [line.rstrip('\n') for line in urlst]
#handle sig, cert, errors
def handler(signum, frame):
    res = input(" Ctrl-c was pressed. Do you really want to exit? y/n ")
    if res == 'y':
        exit(1)
signal.signal(signal.SIGINT, handler)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="""Caught 'unbalanced parenthesis at position 119' compiling regex""", category=UserWarning )

#install gecko webdriver if not already installed
geckodriver_autoinstaller.install()

#create project directory if not exist and misc 
prjdir = "projects/"+project
scrdir = prjdir+"/screenshots/"
newlist = prjdir+'/newurlist.txt'
tdir = "./template/"
tname = "_layout.html"
dirok = prjdir+"/dir200.txt"
Path(scrdir).mkdir(parents=True, exist_ok=True)
jdata = []
wap = Wappalyzer.latest()
headers = {
	'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'
		}

#make the requests
def doit(URL):
	for letter in 'a':
		try:
			URL1 = URL.strip()
			rndm = ''.join(random.choices(string.ascii_lowercase, k=3))
			domain = urlparse(URL1).netloc
			scrname = domain+"-"+rndm+".png"
			scrn1 = scrdir+scrname
			scrn2 = "screenshots/"+scrname
			#ff webdriver
			fireFoxOptions = webdriver.FirefoxOptions()
			fireFoxOptions.set_preference("general.useragent.override", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36")
			fireFoxOptions.setAcceptInsecureCerts = True
			fireFoxOptions.setAssumeUntrustedCertificateIssuer = True
			fireFoxOptions.accept_untrusted_certs = True
			fireFoxOptions.headless = True
			driver = webdriver.Firefox(options=fireFoxOptions)
			driver.set_page_load_timeout(15)
			driver.get(URL1)
			time.sleep(2)
			utitle = driver.title
			if utitle == "":
				utitle = "No Title"
			driver.save_screenshot(scrn1)
			print("[#] screenshot success     - "+URL1)
			gettech(URL1, domain)
		except TimeoutException as t:
			print("[-] screenshot timeout     - "+URL1)
			driver.quit()
			continue
		except (NoSuchElementException, WebDriverException) as e:
			print(e)
			print("[-] screenshot unreachable - "+URL1)
			driver.quit()
			continue
		finally:
			try:
				k = {"Address":URL1,"Image":scrn2,"Tech":gettech.wapres1,"Title":utitle}
				jdata.append(k)
				driver.quit()
			except:
				driver.quit()

#wappalyzer
def gettech(URL1, domain):
	response = requests.get(URL1, headers=headers, timeout=8)
	wappage = WebPage.new_from_response(response)
	wapres = wap.analyze_with_versions(wappage)
	gettech.wapres1 = '  '.join(f'{value}' for value in wapres)
	if gettech.wapres1 == "":
		exit
	else:
		print("[#] wappalyzer response    - "+URL1+": "+str(gettech.wapres1))

#handle threading if multiple urls or brute force
def tpool():
	print("[*] Saving url screenshot(s) in "+scrdir+" directory")
	if target and brlst:
		URL = target
		brutef(URL)
		mergeit()
	elif target:
		URL = target
		doit(URL)
	elif urlist and brlst:
		URL = 'https://what.com'
		brutef(URL)
		mergeit()
	elif urlst:
		sworker(urlist)

#all the screenshots init
def sworker(urlist):
	LENGTH = len(urlist)
	with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
		with Progress() as progress:
			task2 = progress.add_task("[green]Takeing screenshots: ", total=LENGTH)
			future_to_url = {executor.submit(doit, URL): URL for URL in urlist}
			for _ in as_completed(future_to_url):
				progress.update(task2, advance=1)

#brute force dirs threading
def brutef(URL):
	brlist = [line.rstrip('\n') for line in brlst]
	LENGTH = len(brlist)
	if urlist:
		for URL in urlist:
			with concurrent.futures.ThreadPoolExecutor(max_workers=75) as executor:
				with Progress() as progress:
					task1 = progress.add_task("[green]Discovering resources: "+URL, total=LENGTH)
					future_to_dir = {executor.submit(checkpath, URL, DIR): DIR for DIR in brlist}
					for _ in as_completed(future_to_dir):
						progress.update(task1, advance=1)
	else:
		with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
			with Progress() as progress:
				task1 = progress.add_task("[green]Discovering resources: "+URL, total=LENGTH)
				future_to_dir = {executor.submit(checkpath, URL, DIR): DIR for DIR in brlist}
				for _ in as_completed(future_to_dir):
					progress.update(task1, advance=1)

#brute force dirs
def checkpath(URL, DIR):
	try:
		URL1=URL.strip()
		DIR1 = DIR.strip()
		durl = URL+"/"+DIR1
		d = requests.get(durl, headers=headers, timeout=4)
		if d.ok:
			ds = len(d.content)
			dsz = naturalsize(ds)
			#print("[#] discovered url path    - :"+durl+" "+dsz)
			with open(dirok, "a") as dirf:
				dirf.write(durl+"\n")
				dirf.close
	except:
		a=b

#merge user provided url list with found urls
def mergeit():
	okok = Path(dirok)
	if okok.exists() and urlst:
		with open(dirok) as fp:
			data = fp.read()
		with open(urlst.name) as fp:
			data2 = fp.read()
		data += data2
		with open(newlist, 'w') as fp:
			fp.write(data)
		with open(newlist, 'r') as fd:
			urlist1 = fd.readlines()
		urlist = [line.rstrip('\n') for line in urlist1]
		sworker(urlist)
	elif urlst:
		sworker(urlist)
	elif okok.exists() and target:
		with open(dirok) as fp:
			data = fp.read()
		data += target
		with open(newlist, 'w') as fp:
			fp.write(data)
		with open(newlist, 'r') as fd:
			urlist = fd.readlines()
		sworker(urlist)
	else:
		doit(URL)

#render html with jinja
def jin(directory, template_name, data):
	print("[*] Saving final output to "+prjdir+"/index.html")
	try:
		loader = jinja2.FileSystemLoader(searchpath=directory)
		jenv = jinja2.Environment(loader=loader)
		template = jenv.get_template(template_name)
		htmlout = template.render(jdata=jdata)
		file = open(prjdir+"/index.html", "w")
		file.write(htmlout)
		file.close
	except Exception as e:
		print("[*] Saving final output failed with: "+str(e))
	
if __name__ == "__main__":
	tpool()
	jin(tdir, tname, jdata)
