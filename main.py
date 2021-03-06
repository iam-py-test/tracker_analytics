import requests
from bs4 import BeautifulSoup
from tranco import Tranco
from urllib.parse import urlparse

# setup
t = Tranco(cache=True, cache_dir='.tranco')
latest_top = t.list().top(70)
extratrackerdomains = ["google-analytics.com","ssl.google-analytics.com","www.google-analytics.com","www-google-analytics.l.google.com","googletagmanager.com","www.googletagmanager.com","static-doubleclick-net.l.google.com","www-googletagmanager.l.google.com","ssl-google-analytics.l.google.com","googlesyndication.com","wwwctp.googletagmanager.com","wp.googletagmanager.com","googletagservices.com","www.googletagservices.com","doubleclick.net","securepubads.g.doubleclick.net","geo.yahoo.com","go-mpulse.net","collector.githubapp.com","s3.buysellads.com","collector.github.com"]
trackerdomains = requests.get("https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0&mimetype=plaintext").text.split("\n")
trackerdomains += extratrackerdomains
malwaredomains = requests.get("https://raw.githubusercontent.com/iam-py-test/my_filters_001/main/Alternative%20list%20formats/antimalware_domains.txt").text.split("\n")
# don't visit ip loggers & adfly
disalloweddomains = ["iplogger.com","iplogger.org","grabify.link","adf.ly"]
data = {"domains_tested":0,"domains_with_tracker":0,"domains_with_HTTPS":0,"per_domain_stats":{}}

# functions
def hasHTTPS(domain):
  try:
    requests.get("https://{}".format(domain),allow_redirects=False)
  except:
    return False
  else:
    return True
def hastrackers(html,d=""):
  report = {"total":0,"has_trackers":False}
  try:         
      if d in trackerdomains:
            print("direct",d)
            report["total"] += 1
            report["has_trackers"] = True
            return report
  except:
      pass
  soup = BeautifulSoup(html,'html.parser')
  pf = soup.select("link[rel=\"dns-prefetch\"]")
  for prefetch in pf:
      try:
        domain = urlparse(prefetch.get("href")).netloc
        if domain in trackerdomains and domain != "":
            print("prefetch",domain)
            report["total"] += 1
            report["has_trackers"] = True
            return report
      except Exception as err:
        pass
  try:
    soup = BeautifulSoup(html,'html.parser')
    scripts = soup.find_all("script")
    for script in scripts:
      try:
        domain = urlparse(script.get("src")).netloc
        if domain in trackerdomains and domain != "":
            print("src",domain)
            report["total"] += 1
            report["has_trackers"] = True
            return report
      except:
        pass
      try:
        maybetracker_contents = script.content
        if len(maybetracker_contents) > 5:
          for tracker_domain in trackerdomains:
              if tracker_domain in maybetracker_contents:
                print("contents",tracker_domain)
                report["total"] += 1
                report["has_trackers"] = True
                return report
      except Exception as err:
        pass
    try:
      csps = soup.select("meta[http-equiv=\"Content-Security-Policy\"]")
      csptext = csps[0].get("content")
      print(csptext)
    except:
      pass
    
  except:
    return report
  else:
    return report
    

for domain in latest_top:
  if domain in malwaredomains:
    print("Avoided going to malware domain '{}'".format(domain))
  elif domain in disalloweddomains:
    print("Disallowed domain {} avoided".format(domain))
  elif domain not in malwaredomains:
    try:
      req = requests.get("http://{}".format(domain))
      data["domains_tested"] += 1
      domainreport = hastrackers(req.text,domain)
      if domainreport["has_trackers"] == True:
        data["domains_with_tracker"] += 1
      hassec = hasHTTPS(domain)
      if hassec:
        data["domains_with_HTTPS"] += 1
      data["per_domain_stats"][domain] = {"hasHTTPS":hassec,"has_trackers":domainreport["has_trackers"]}
    except Exception as err:
      print(err)

with open("report.md","w") as f:
  f.write("## Tracker report\n")
  f.write("{} domains tested <br>\n".format(data["domains_tested"]))
  f.write("{} of the domains tested used known trackers <br>\n".format(data["domains_with_tracker"]))
  f.write("{} of the domains tested supported HTTPS <br>\n".format(data["domains_with_HTTPS"]))
  f.write("\n\n### Individual domain statistics: ")
  
  for entry in data["per_domain_stats"]:
    f.write("\n\n\n#### {}".format(entry))
    f.write("\nHTTPS: {}".format(data["per_domain_stats"][entry]["hasHTTPS"]))
    f.write("\n<br>Known trackers: {}".format(data["per_domain_stats"][entry]["has_trackers"]))
  f.close()
