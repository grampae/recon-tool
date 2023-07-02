#!/usr/bin/python3
from Wappalyzer import Wappalyzer, WebPage
from concurrent.futures import ThreadPoolExecutor, as_completed
from humanize import naturalsize
from os import getcwd
from pathlib import Path
from rich.progress import Progress
from selenium import webdriver
from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service as FirefoxService
from urllib.parse import urlparse
from webdriver_manager.firefox import GeckoDriverManager
from collections import Counter
from patterns import xxx as xxx
import re
import argparse
import concurrent.futures
import geckodriver_autoinstaller
import jinja2
import logging
import random
import requests
import shodan
import signal
import string
import sys
import time
import urllib3
import warnings

#handle argument parsing
parser = argparse.ArgumentParser(description="Screenshots r us", formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-t", dest="single", required=False, help="Single target, ex: http(s)://target.com")
parser.add_argument("-l", dest="urlst", required=False, type=argparse.FileType("r", encoding="UTF-8"), help="List of urls")
parser.add_argument("-p", dest="project", required=True, help="Project name")
args = parser.parse_args()
if len(sys.argv)==1:
    parser.print_help(sys.stderr)
    sys.exit(1)
project = args.project
target = args.single
urlst = args.urlst

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
logging.getLogger(requests.packages.urllib3.__package__).setLevel(logging.ERROR)

#install gecko webdriver if not already installed
geckodriver_autoinstaller.install()

#create project directory if not exist and misc 
cwd = getcwd()
prjdir = "projects/"+project
scrdir = prjdir+"/screenshots/"
waydir = cwd+"/"+prjdir+"/wayback/"
tdir = "./template/"
tname = "_layout.html"
Path(scrdir).mkdir(parents=True, exist_ok=True)
Path(waydir).mkdir(parents=True, exist_ok=True)
waybls = []
jdata = []
wdata = []
pdata = {"Project":project}
wap = Wappalyzer.latest()
headers = {
	'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'
		}
#shodan api
apikey = "tbTdhMDL7JgsabccwGLoJqZyI6uJK6Fj"
api = shodan.Shodan(apikey)

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
			html = driver.page_source
			time.sleep(3)
			utitle = driver.title
			if utitle == "":
				utitle = "No Title"
			driver.save_screenshot(scrn1)
			print("[#] screenshot success     - "+URL1)
			hsecret(URL1, html)
			driver.quit()
			gettech(URL1, domain)
			waybm(URL1, domain)
			shownuff(URL1)
		except ConnectionError:
			print('Connection Error')
			driver.quit()
			continue
		except TimeoutException as t:
			print("[-] screenshot timeout     - "+URL1)
			driver.quit()
			continue
		except (NoSuchElementException, WebDriverException) as fu:
			print("[-] screenshot unreachable - "+URL1)
			driver.quit()
			break
		except Exception as e:
			print("Error: "+e)
			driver.quit()
			break
		finally:
			try:
				if "heyoo" not in (waybm.wow, shownuff.surl):
					k = {"Address":URL1,"Image":scrn2,"Tech":gettech.wapres1,"Title":utitle, "Wayback":waybm.wow, "Shodan":shownuff.surl}
				elif "heyoo" in waybm.wow and "heyoo" not in shownuff.surl:
					k = {"Address":URL1,"Image":scrn2,"Tech":gettech.wapres1,"Title":utitle, "Shodan":shownuff.surl}
				elif "heyoo" in shownuff.surl and "heyoo" not in waybm.wow:
					k = {"Address":URL1,"Image":scrn2,"Tech":gettech.wapres1,"Title":utitle, "Wayback":waybm.wow}
				else:
					k = {"Address":URL1,"Image":scrn2,"Tech":gettech.wapres1,"Title":utitle}
				jdata.append(k)
				driver.quit()
			except:
				driver.quit()
				continue

#find secrets and errors
def hsecret(URL1,html):
	try:
		for hname, hpattern in xxx.items():
			for value in hpattern:
				hresult = re.search(hpattern['regex'], html)
				if hresult:
					#print(hresult.group(1))
					print("[#] regex match            - "+URL1+": "+hpattern['name']+" "+hresult.group(0)[:100])
					hsecret.fname = prjdir+'/regexmatch.txt'
					with open(hsecret.fname, 'a') as hsec:
						hsec.write(URL1+": "+hpattern['name']+" "+hresult.group(0)[:100]+"\n")
	except Exception as e:
		print("Error: "+e)
#wappalyzer
def gettech(URL1, domain):
	try:
		response = requests.get(URL1, headers=headers, timeout=8, verify=False)
		wappage = WebPage.new_from_response(response)
		wapres = wap.analyze(wappage)
		gettech.wapres1 = '  '.join(f'{value}' for value in wapres)
		gettech.graph1 = gettech.wapres1
		if gettech.wapres1 == "":
			exit
		else:
			print("[#] wappalyzer response    - "+URL1+": "+str(gettech.wapres1))
			for x in wapres:
				wdata.append(x)
	except ConnectionError:
		print("[!] wappalyzer response    - "+URL1+": Connection Error")
	except Exception as e:
		print("[!] wappalyzer response    - "+URL1+": Connection Error"+e)

#wayback machine
def waybm(URL1,domain):
	try:
		wayb = "http://web.archive.org/cdx/search/cdx?url="+URL1+"*&output=text"
		time.sleep(3)
		with requests.get(wayb, headers=headers, verify=False, timeout=8) as waybmr:
			if waybmr.text  == "":
				waybm.wow = "heyoo"
				exit
			else:
				waybm.wow = waydir+domain+".txt"
				print("[#] wayback urls found     - "+URL1+": "+prjdir+"/wayback/"+domain+".txt")
				waybml = waybmr.text
				line2 = waybml.splitlines()
				for line3 in line2:
					ab=line3.split()[2]
					waybls.append(ab)
				waybls2 = (set(waybls))
				with open(waybm.wow, 'a') as wu:
					for wurl in waybls2:
						wu.write("%s\n" % wurl)
	except ConnectionError:
		print("[!] wayback response       - "+URL1+": Connection Error")
	except Exception as f:
		print("[!] wayback response       - "+URL1+": Connection Error")

#shodan api
def shownuff(URL1):
	try:
		shownuff.surl = "heyoo"
		baseip = urlparse(URL1).hostname
		sresults = bleh
		for sresult in sresults['matches']:
			print('[#] shodan discovered port - '+baseip+': Open port {}'.format(sresult['port']))
			if sresult['port']:
				shownuff.surl = "https://www.shodan.io/search?query="+baseip
	except shodan.APIError as e:
		print('Error: {}'.format(e))

#handle threading if multiple urls
def tpool():
	print("[*] Saving url screenshot(s) in "+scrdir+" directory")
	if target:
		URL = target
		doit(URL)
	elif urlst:
		sworker(urlist)

#all the screenshots init
def sworker(urlist):
	LENGTH = len(urlist)
	with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
		with Progress() as progress:
			task2 = progress.add_task("[green]Takeing screenshots: ", total=LENGTH)
			future_to_url = {executor.submit(doit, URL): URL for URL in urlist}
			for _ in as_completed(future_to_url):
				progress.update(task2, advance=1)
				
#add additional template variables and functions
def proj_name():
    return project

def waptotal():
	wtup = tuple(i for i in wdata)
	abra = len(list(wdata))
	if abra >= 10:
		waptotal.cadabra = 10
		wapwap = Counter(wtup).most_common(waptotal.cadabra)
		return("\'"+wapwap[0][0]+"\',\'"+wapwap[1][0]+"\',\'"+wapwap[2][0]+"\',\'"+wapwap[3][0]+"\',\'"+wapwap[4][0]+"\',\'"+wapwap[5][0]+"\',\'"+wapwap[6][0]+"\',\'"+wapwap[7][0]+"\',\'"+wapwap[8][0]+"\',\'"+wapwap[9][0]+"\'")
	elif abra > 5 and abra < 10:
		waptotal.cadabra = 5
		wapwap = Counter(wtup).most_common(waptotal.cadabra)
		return("\'"+wapwap[0][0]+"\',\'"+wapwap[1][0]+"\',\'"+wapwap[2][0]+"\',\'"+wapwap[3][0]+"\',\'"+wapwap[4][0]+"\'")
	elif abra < 5:
		waptotal.cadabra = 0
		return("'not enough data'")


def waptotal2():
	wtup = tuple(i for i in wdata)
	abra = len(list(wdata))
	if abra >= 10:
		cadabra = 10
		wapwap = Counter(wtup).most_common(cadabra)
		return(str(wapwap[0][1])+","+str(wapwap[1][1])+","+str(wapwap[2][1])+","+str(wapwap[3][1])+","+str(wapwap[4][1])+","+str(wapwap[5][1])+","+str(wapwap[6][1])+","+str(wapwap[7][1])+","+str(wapwap[8][1])+","+str(wapwap[9][1]))
		return(elguapo)
	elif abra > 5 and abra < 10:
		cadabra = 5
		wapwap = Counter(wtup).most_common(cadabra)
		return(str(wapwap[0][1])+","+str(wapwap[1][1])+","+str(wapwap[2][1])+","+str(wapwap[3][1])+","+str(wapwap[4][1]))
	elif abra < 5:
		return("1")

template_funcs = {
    "proj_name": proj_name,
    "waptotal": waptotal,
    "waptotal2": waptotal2
}

#render html with jinja
def jin(directory, template_name, data):
	time.sleep(2)
	try:
		loader = jinja2.FileSystemLoader(searchpath=directory)
		jenv = jinja2.Environment(loader=loader)
		template = jenv.get_template(template_name)
		template.globals.update(template_funcs)
		htmlout = template.render(jdata=jdata)
		file = open(prjdir+"/index.html", "w")
		file.write(htmlout)
		file.close
		print("[*] Saved final output to "+prjdir+"/index.html")
	except Exception as e:
		print("[*] Saving final output failed with: "+str(e))
	
if __name__ == "__main__":
	tpool()
	#waptotal()
	jin(tdir, tname, jdata)
