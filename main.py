import requests
import socket
import urllib
from bs4 import BeautifulSoup
from tranco import Tranco
from urllib.parse import urlparse
import re

DOMAINS_TO_SCAN = 200

# setup
t = Tranco(cache=True, cache_dir='.tranco')
latest_top = sorted(t.list().top(DOMAINS_TO_SCAN))
extratrackerdomains = ["google-analytics.com","ssl.google-analytics.com","www.google-analytics.com","www-google-analytics.l.google.com","googletagmanager.com","www.googletagmanager.com","static-doubleclick-net.l.google.com","www-googletagmanager.l.google.com","ssl-google-analytics.l.google.com","googlesyndication.com","wwwctp.googletagmanager.com","wp.googletagmanager.com","googletagservices.com","www.googletagservices.com","doubleclick.net","securepubads.g.doubleclick.net","geo.yahoo.com","go-mpulse.net","collector.githubapp.com","s3.buysellads.com","collector.github.com","taboola.com","slackb.com","colpirio.com","ad.360yield.com","analytics.archive.org"]
trackerdomains = requests.get("https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0&mimetype=plaintext").text.split("\n")
trackerdomains += extratrackerdomains
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
script_with_tracker_in_url = re.compile("https?://.*track.{1,30}")
script_with_analytics_in_url = re.compile("https?://.*analytic.*\.js")
script_with_datacollection_in_url = re.compile("https?://.*datacollect.*\.js")
script_with_pageview_in_url = re.compile("https?://.*pageview.*\.js")
script_with_hitcounter_in_url = re.compile("https?://.*hitcount.*\.js")
script_with_ad_targeting_in_url = re.compile("https?://.*ad-target.*\.js")
fetch_with_ping_in_url = re.compile("fetch\(\"https?://.*ping.*\"\)")
trackingID = re.compile(".{0,20}TrackingID")

errlog = open("err.log",'w')

try:
	known_domains_list = open("kdl.txt",'r',encoding="UTF-8").read().split("\n")
except:
	known_domains_list = []

trackers_found_obj = {}

# functions
def hasHTTPS(domain):
	try:
		requests.get("https://{}".format(domain),allow_redirects=False)
	except:
		return False
	else:
		return True
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
				return report
	except:
			pass
	for kts in known_tracker_strings:
		if kts in html and kts != "" and kts != " " and kts != "\r":
			print(kts)
			report["total"] += 1
			report["has_trackers"] = True
			break
	# extract all sus strings for analysis by me
	try:
		if report["has_trackers"] == False:
			suspect_strings += re.findall(script_with_tracker_in_url, html)
			suspect_strings += re.findall(script_with_analytics_in_url, html)
			suspect_strings += re.findall(script_with_datacollection_in_url, html)
			suspect_strings += re.findall(script_with_pageview_in_url, html)
			suspect_strings += re.findall(script_with_hitcounter_in_url, html)
			suspect_strings += re.findall(script_with_ad_targeting_in_url, html)
			suspect_strings += re.findall(fetch_with_ping_in_url, html)
			suspect_strings += re.findall(trackingID, html)
	except Exception as err:
		print("regex error: ",err)
	
	soup = BeautifulSoup(html,'html.parser')
	pf = soup.select("link[rel=\"dns-prefetch\"]")
	for prefetch in pf:
			try:
				domain = urlparse(prefetch.get("href")).netloc
				if domain in trackerdomains and domain != "":
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
		scripts = soup.find_all("script")
		for script in scripts:
			hassrc = False
			try:
				srcurl = urllib.parse.urljoin("http://{}".format(d),script.get("src"))
				if srcurl in known_tracker_urls:
					report["total"] += 1
					report["has_trackers"] = True
				domain = urlparse(srcurl).netloc
				hassrc = True
				if domain not in known_domains_list and domain != "":
					known_domains_list.append(domain)
				if domain in trackerdomains and domain != "":
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
			req = requests.get("http://{}".format(domain))
			data["domains_tested"] += 1
			domainreport = hastrackers(req.text,domain)
			if domainreport["has_trackers"] == True:
				data["domains_with_tracker"] += 1
			hassec = hasHTTPS(domain)
			if hassec:
				data["domains_with_HTTPS"] += 1
			data["per_domain_stats"][domain] = {"hasHTTPS":hassec,"has_trackers":domainreport["has_trackers"],"total":domainreport["total"],"endurl":req.url}
		except Exception as err:
			failedtoscan += 1
			errlog.write("[{}] {}\n".format(domain,err))

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
	
	f.write("\n### Statistics for each tracker\n")
	for trackerf in trackers_found_obj:
		f.write("`{}`: {}<br>\n".format(trackerf,trackers_found_obj[trackerf]))
	f.close()
kdl_out = open("kdl.txt",'w',encoding="UTF-8")
kdl_out.write("\n".join(known_domains_list))
kdl_out.close()
sus_out = open("suspect_strings",'w',encoding="UTF-8")
sus_out.write("\n".join(suspect_strings))
sus_out.close()
