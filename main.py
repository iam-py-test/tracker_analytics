import requests
import socket
import urllib
from bs4 import BeautifulSoup
from tranco import Tranco
from urllib.parse import urlparse
import re
import publicsuffixlist
import dns.resolver

DOMAINS_TO_SCAN = 200

# setup
psl = publicsuffixlist.PublicSuffixList()
t = Tranco(cache=False)
latest_top = sorted(t.list().top(DOMAINS_TO_SCAN))
extratrackerdomains = ["google-analytics.com","ssl.google-analytics.com","www.google-analytics.com","www-google-analytics.l.google.com","googletagmanager.com","www.googletagmanager.com","static-doubleclick-net.l.google.com","www-googletagmanager.l.google.com","ssl-google-analytics.l.google.com","googlesyndication.com","wwwctp.googletagmanager.com","wp.googletagmanager.com","googletagservices.com","www.googletagservices.com","doubleclick.net","securepubads.g.doubleclick.net","geo.yahoo.com","go-mpulse.net","collector.githubapp.com","s3.buysellads.com","collector.github.com","taboola.com","slackb.com","colpirio.com","ad.360yield.com","analytics.archive.org", "sentry.dev"]
trackerdomains = requests.get("https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0&mimetype=plaintext").text.split("\n")
trackerdomains += extratrackerdomains
trackerdomains += requests.get("https://raw.githubusercontent.com/iam-py-test/my_filters_001/main/Alternative%20list%20formats/anti-privacy-analytics_domains.txt").text.replace("\r", "").split("\n")
malwaredomains = requests.get("https://raw.githubusercontent.com/iam-py-test/my_filters_001/main/Alternative%20list%20formats/antimalware_domains.txt").text.split("\n")
known_tracker_strings_filehandle = open('known_tracker_strings.txt',encoding="UTF-8")
known_tracker_strings = known_tracker_strings_filehandle.read().split("\n")
known_tracker_urls = ["https://static.cloud.coveo.com/coveo.analytics.js/coveoua.js"]
# don't visit ip loggers, adf.ly, etc
disalloweddomains = ["iplogger.com","iplogger.org","grabify.link","adf.ly","lyksoomu.com","localhost"]
# don't scan allowlisted scripts
excluded_scripts = ["code.jquery.com"]
data = {"domains_tested":0,"domains_with_tracker":0,"domains_with_HTTPS":0,"per_domain_stats":{}}
abletoscan = 0
failedtoscan = 0
suspect_strings = []
# regexs to extract possible trackers
script_with_tracker_in_url = re.compile("https?://[a-zA-Z./]*tracker[a-zA-Z./]*\.js")
script_with_analytics_in_url = re.compile("https?://[a-zA-Z./]*analytics[a-zA-Z./]*\.js")
script_with_datacollection_in_url = re.compile("https?://[a-zA-Z./]*datacollect[a-zA-Z./]*\.js")
script_with_pageview_in_url = re.compile("https?://[a-zA-Z./]*pageview[a-zA-Z./]*\.js")
script_with_hitcounter_in_url = re.compile("https?://[a-zA-Z./]*hitcount[a-zA-Z./]*\.js")
script_with_ad_targeting_in_url = re.compile("https?://[a-zA-Z./]*ad-target[a-zA-Z./]*\.js")
dnsr = dns.resolver.Resolver()

errlog = open("err.log",'w')

try:
	known_domains_list = open("kdl.txt",'r',encoding="UTF-8").read().split("\n")
except:
	known_domains_list = []

try:
	known_urls_list = open("kul.txt",'r',encoding="UTF-8").read().split("\n")
except:
	known_urls_list = []

trackers_found_obj = {}

# functions
def hasHTTPS(domain):
	try:
		requests.get("https://{}".format(domain),allow_redirects=False)
	except:
		return False
	else:
		return True
def get_cname(domain):
	global known_domains_list
	try:
		response = dnsr.resolve(domain)
		cname = response.canonical_name.to_text()
		if cname.endswith("."):
			cname = cname[:-1]
		if cname not in known_domains_list:
			known_domains_list.append(cname)
		return cname
	except:
		return domain
def hastrackers(html,d=""):
	global trackers_found_obj
	global known_domains_list
	global suspect_strings
	report = {"total":0,"has_trackers":False}
	try:
			if d in trackerdomains:
				report["total"] += 1
				report["has_trackers"] = True
				if d not in trackers_found_obj:
					trackers_found_obj[d] = 0
				trackers_found_obj[d] += 1
	except:
			pass
	for kts in known_tracker_strings:
		if kts in html and kts != "" and kts != " " and kts != "\r":
			#print(kts)
			report["total"] += 1
			report["has_trackers"] = True
			break
	
	soup = BeautifulSoup(html,'html.parser')
	pf = soup.select("link")
	for prefetch in pf:
			try:
				full_url = urllib.parse.urljoin("http://{}".format(d),prefetch.get("href"))
				if full_url == "":
					continue
				domain = urlparse(full_url).netloc
				root = psl.privatesuffix(domain)
				cname = get_cname(domain)
				if (domain in trackerdomains or root in trackerdomains or cname in trackerdomains) and domain != "":
						print(domain, root)
						report["total"] += 1
						report["has_trackers"] = True
						if domain not in trackers_found_obj:
							trackers_found_obj[domain] = 0
						trackers_found_obj[domain] += 1
				if domain not in known_domains_list and domain != "":
					known_domains_list.append(domain)
				if full_url not in known_urls_list:
					known_urls_list.append(full_url)
			except Exception as err:
				pass
	forms = soup.select("form")
	for form in forms:
			try:
				domain = urlparse(urllib.parse.urljoin("http://{}".format(d),form.get("action"))).netloc
				root = psl.privatesuffix(domain)
				cname = get_cname(domain)
				if (domain in trackerdomains or root in trackerdomains or cname in trackerdomains) and domain != "":
						print(domain, root)
						report["total"] += 1
						report["has_trackers"] = True
						if domain not in trackers_found_obj:
							trackers_found_obj[domain] = 0
						trackers_found_obj[domain] += 1
				if domain not in known_domains_list and domain != "":
					known_domains_list.append(domain)
			except Exception as err:
				pass
	try:
		links = soup.select("a")
		for link in links:
			hassrc = False
			try:
				srcurl = urllib.parse.urljoin("http://{}".format(d),link.get("ping"))
				if srcurl in known_tracker_urls:
					report["total"] += 1
					report["has_trackers"] = True
				domain = urlparse(srcurl).netloc
				root = psl.privatesuffix(domain)
				cname = get_cname(domain)
				hassrc = True
				if domain not in known_domains_list and domain != "":
					known_domains_list.append(domain)
				if srcurl not in known_urls_list:
					known_urls_list.append(srcurl)
				if (domain in trackerdomains or root in trackerdomains or cname in trackerdomains) and domain != "":
						report["total"] += 1
						report["has_trackers"] = True
						if domain not in trackers_found_obj:
							trackers_found_obj[domain] = 0
						trackers_found_obj[domain] += 1
			except Exception as err:
				pass
	except:
		pass
	try:
		scripts = soup.select("[src]")
		for script in scripts:
			hassrc = False
			try:
				srcurl = urllib.parse.urljoin("http://{}".format(d),script.get("src"))
				if srcurl in known_tracker_urls:
					report["total"] += 1
					report["has_trackers"] = True
				domain = urlparse(srcurl).netloc
				root = psl.privatesuffix(domain)
				cname = get_cname(domain)
				hassrc = True
				if domain not in known_domains_list and domain != "":
					known_domains_list.append(domain)
				if (domain in trackerdomains or root in trackerdomains or cname in trackerdomains) and domain != "":
						report["total"] += 1
						report["has_trackers"] = True
						if domain not in trackers_found_obj:
							trackers_found_obj[domain] = 0
						trackers_found_obj[domain] += 1
			except Exception as err:
				pass
		return report
		
	except:
		return report
	else:
		return report
		

for domain in latest_top:
	if domain in malwaredomains or domain in disalloweddomains:
		print("Avoided going to domain '{}'".format(domain))
		failedtoscan += 1
	else:
		try:
			try:
				req = requests.get("http://{}".format(domain))
			except Exception as err:
				try:
					req = requests.get("https://{}".format(domain))
					print("Retried and got a response")
				except Exception as err:
					failedtoscan += 1
					errlog.write("[{}] {}\n".format(domain,err))
					continue
			if req.url not in known_urls_list:
				known_urls_list.append(req.url)
			data["domains_tested"] += 1
			domainreport = hastrackers(req.text,domain)
			if domainreport["has_trackers"] == True:
				data["domains_with_tracker"] += 1
			hassec = hasHTTPS(domain)
			if hassec:
				data["domains_with_HTTPS"] += 1
			data["per_domain_stats"][domain] = {"hasHTTPS":hassec,"has_trackers":domainreport["has_trackers"],"total":domainreport["total"],"endurl":req.url, "encoding": req.encoding}
		except Exception as err:
			failedtoscan += 1
			errlog.write("[{}] {}\n".format(domain,err))
			continue

with open("report.md","w") as f:
	f.write("## Tracker report\n")
	f.write("Tried to test {} domains<br>\n".format(DOMAINS_TO_SCAN))
	f.write("{} domains tested <br>\n".format(data["domains_tested"]))
	f.write("Failed to test {} domains <br>\n".format(failedtoscan))
	f.write("{} of the domains tested used known trackers <br>\n".format(data["domains_with_tracker"]))
	f.write("{} of the domains tested supported HTTPS <br>\n".format(data["domains_with_HTTPS"]))
	f.write("\n\n### Individual domain statistics: ")
	
	for entry in data["per_domain_stats"]:
		f.write("\n\n\n#### {}".format(entry))
		f.write("\nHTTPS: {} <br>".format(data["per_domain_stats"][entry]["hasHTTPS"]))
		f.write("\nKnown trackers: {} <br>".format(data["per_domain_stats"][entry]["has_trackers"]))
		f.write("\nNumber of trackers detected: {} <br>".format(data["per_domain_stats"][entry]["total"]))
		f.write("\nResponse encoding: {} <br>".format(data["per_domain_stats"][entry]["encoding"]))
	
	f.write("\n### Statistics for each tracker\n")
	for trackerf in trackers_found_obj:
		f.write("`{}`: {}<br>\n".format(trackerf,trackers_found_obj[trackerf]))
	f.close()
kdl_out = open("kdl.txt",'w',encoding="UTF-8")
kdl_out.write("\n".join(known_domains_list))
kdl_out.close()
kdl_out = open("kul.txt",'w',encoding="UTF-8")
kdl_out.write("\n".join(known_urls_list))
kdl_out.close()
sus_out = open("suspect_strings",'w',encoding="UTF-8")
sus_out.write("\n".join(suspect_strings))
sus_out.close()
