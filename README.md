minesweeper
===========

Minesweeper scans websites to detect drive-by malware.

## Install

These docs are for Ubuntu 14.04 and are for a non-root user with sudo privilege.

### Nginx

Install nginx as a reverse proxy so that we don't have to run minesweeper as root
```
sudo apt-get install nginx
```

### PhantomJS

Install phantomjs, minesweeper's headless browser of choice
```
sudo apt-get install phantomjs
```

### Suricata

Install suricata + emerging threats rules
```
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install suricata
```

Edit /etc/suricata/suricata.yaml
```
af-packet.interface: lo
outputs.fast.enabled: yes
HOME_NET="127.0.0.1"
EXTERNAL_NET="127.0.0.1" in /etc/suricata/suricata.yaml
HTTP_PORTS="1024:" in /etc/suricata/suricata.yaml
host-os-policy.windows: [] in /etc/suricata/suricata.yaml
host-os-policy.linux: [0.0.0.0/0] in /etc/suricata/suricata.yaml
```

Start Suricata
```
sudo service suricata start
```

### Google

Grab a Google API key from https://developers.google.com/safe-browsing/lookup_guide#GettingStarted

### tcpdump

Allow a non-root user to capture with tcpdump
```
sudo setcap "cap_net_raw+eip" /usr/sbin/tcpdump
```

### Minesweeper

Download
```
curl -O https://github.com/Shopify/minesweeper/releases/download/0.2.0/minesweeper-0.2.0-linux-amd64.tar.gz
```

Extract
```
tar xzf minesweeper-0.2.0-linux-amd64.tar.gz
cd minesweeper-0.2.0-linux-amd64
```

Install binary
```
sudo cp minesweeper /usr/local/bin/
```

Edit and Install upstart script
```
set "env MINESWEEPER_GOOGLE_API_KEY=" to your Google API Key in /etc/init/minesweeper.conf
sudo cp minesweeper.conf /etc/init/
```

Start minesweeper
```
sudo service minesweeper start
```

## Test

Minesweeper listens on 127.0.0.1:6463 by default.

E.g. Scan it.
```
$ curl http://localhost:6463/scan?url=ianfette.org
{
  "Verdict": "suspicious",
  "ReportId": "20141201202108-214329780"
}
```

E.g. Get Report.
```
$ curl http://localhost:6463/report?id=20141201202108-214329780
{
  "Id": "20141201202108-214329780",
  "Url": "http://ianfette.org",
  "Verdict": "suspicious",
  "CreatedAt": "Mon Dec  1 20:21:08 UTC 2014",
  "Resources": [
    {
      "Method": "GET",
      "Url": "http://ianfette.org/",
      "Status": 200,
      "ContentType": "text/html",
      "ContentLength": 43,
      "MinesweeperSha256": "0e7d00142cf0f74c7e4d5b2469c016bd421837ce692cd6a276fce2f3d5fc3a06",
      "MinesweeperSniffedMime": "text/html; charset=utf-8"
    }
  ],
  "Changes": null,
  "Hits": [
    {
      "BlacklistName": "google",
      "Url": "http://ianfette.org/",
      "Domain": "ianfette.org",
      "Type": "malware",
      "Ref": "https://developers.google.com/safe-browsing/developers_guide_v3"
    }
  ],
  "Alerts": null
}
```

E.g. Get PCAP.
```
$ curl http://localhost:6463/pcap?id=20141201202108-214329780 > foo.pcap
$ file foo.pcap
foo.pcap: tcpdump capture file (little-endian) - version 2.4 (Ethernet, capture length 65535)
```

## How does it work?

Minesweeper will scan a URL, perform a security analysis and say it's `suspicious` or `ok`.

A `suspicious` verdict means that a module has produced a positive (blacklist) `hit` or (IDS) `alert`.

Currently, there are 3 modules: [`malwaredomains`](blacklist/malwaredomains.go), [`google`](blacklist/google.go) and [`suricata`](ids/suricata.go).

**Minesweeper scans websites using [PhantomJS](http://phantomjs.org/) through a local MITM proxy**

* It records:
  * HTTP requests for resources such as Javascript and CSS files
    * URL, Method, Status, Content-Type
    * A sha256 sum for a file - useful for submitting to [VirusTotal](https://www.virustotal.com/)
    * A MIME-sniffed Content-Type determined using [DetectContentType](http://golang.org/pkg/net/http/#DetectContentType)
  * Javascript calls to `document.write()`
    * The HTML to be written is recorded
    * A stack trace is captured to attribute this back to an exact line in the source!
  * Javascript [DOMSubtreeModified](http://www.w3.org/TR/DOM-Level-3-Events/#event-type-DOMSubtreeModified) Mutation Events where the target is either `HTMLScriptElement` or `HTMLIFrameElement`
    * The outer HTML of the modification is recorded

**It captures the traffic between PhantomJS and the local MITM proxy**
* Capturing here means that the IDS has a chance to alert on HTTP request content that will never be seen in a non-proxied environment e.g. a ```<script>``` tag referencing a malicious domain that has been DNS blacklisted.
* In order to enable parallel scans, a separate proxy is setup for each scan.
  * Free ports to listen on are chosen by the operating system by binding to port 0
* By running with a BPF filter for a specific port, we can capture the traffic of each scan separately.

**It grabs any alerts from the [Suricata](http://suricata-ids.org/) IDS which is listening on localhost**
* Alerts written in the fast format are supported `/var/log/suricata/fast.log`
* Minesweeper also greps through your rules files `/etc/suricata/rules/*.rules` to find the full rule text and adds this to each alert

**It also checks all URLs browsed against domain blacklists**
  * Currently, there are 2 blacklists:
      * ```google``` - [Google Safe Browsing Lookup API](https://developers.google.com/safe-browsing/lookup_guide)
      * ```malwaredomains``` - [malwaredomains.com](http://www.malwaredomains.com/)

**It produces a JSON report**
* If there are IDS alerts or Blacklist hits, the website is deemed `suspicious`, otherwise it's `ok`.

## Questions/Suggestions

Don't suffer, just ask! [falsenegative](https://github.com/falsenegative)
