import requests
from bs4 import BeautifulSoup
from tranco import Tranco
from urllib.parse import urlparse

# setup
t = Tranco(cache=True, cache_dir='.tranco')
latest_top = t.list().top(15)
trackerdomains = {"Google":["google-analytics.com","ssl.google-analytics.com","www.google-analytics.com","www-google-analytics.l.google.com","googletagmanager.com","www.googletagmanager.com","static-doubleclick-net.l.google.com","www-googletagmanager.l.google.com","ssl-google-analytics.l.google.com","googlesyndication.com","wwwctp.googletagmanager.com","wp.googletagmanager.com","googletagservices.com","www.googletagservices.com"]}
malwaredomains = requests.get("https://raw.githubusercontent.com/iam-py-test/my_filters_001/main/Alternative%20list%20formats/antimalware_domains.txt").text.split("\n")
data = {"domains_tested":0,"domains_with_tracker":0,"domains_with_HTTPS":0,"per_domain_stats":{}}

# functions
def hasHTTPS(domain):
  try:
    requests.get("https://{}".format(domain))
  except:
    return False
  else:
    return True
def hastrackers(html):
  report = {"Google":False,"total":0,"has_trackers":False}
  try:
    soup = BeautifulSoup(html,'html.parser')
    scripts = soup.find_all("script")
    for script in scripts:
      try:
        domain = urlparse(script.get("src")).netloc
        for tracker_type in trackerdomains:
          if domain in trackerdomains[tracker_type]:
            report[tracker_type] = True
            report["total"] += 1
            report["has_trackers"] = True
      except:
        pass
  except:
    return report
  else:
    return report
    

for domain in latest_top:
  if domain not in malwaredomains:
    try:
      req = requests.get("http://{}".format(domain))
      data["domains_tested"] += 1
      domainreport = hastrackers(req.text)
      if domainreport["has_trackers"] == True:
        data["domains_with_tracker"] += 1
      hassec = hasHTTPS(domain)
      if hassec:
        data["domains_with_HTTPS"] += 1
      data["per_domain_stats"][domain] = {"hasHTTPS":hassec,"has_trackers":domainreport["has_trackers"]}
    except:
      pass

with open("report.md","w") as f:
  f.write("## Tracker report\n")
  f.write("{} domains tested\n".format(data["domains_tested"]))
  f.write("{} of the domains tested used known trackers\n".format(data["domains_with_tracker"]))
  f.write("{} of the domains tested supported HTTPS\n".format(data["domains_with_HTTPS"]))
  f.write("\n\n### Individual domain statistics: ")
  
  for entry in data["per_domain_stats"]:
    f.write("\n\n#### {}".format(entry))
    f.write("HTTPS: {}".format(data["per_domain_stats"][entry]["hasHTTPS"]))
    f.write("Known trackers: {}".format(data["per_domain_stats"][entry]["has_trackers"]))
  f.close()
