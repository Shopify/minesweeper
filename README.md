minesweeper
===========

Minesweeper is a tool to detect websites infected with drive-by malware.

[Shopify](https://github.com/Shopify) uses Minesweeper to protect its 100,000+ online stores from web-based malware infections.

Minesweeper deals with not only the problem of detecting the malware, but also attributing an infection back to a particular asset. It is designed for high speed, parallel operation.

## Install

  1. **Install PhantomJS**
  
  On Mac  
  `brew install phantomjs`  
  On Ubuntu  
  `apt-get install phantomjs`  
  Binary Install  
  ``http://phantomjs.org/download.html``
  
  2. **Install minesweeper**
    
  Download Release v0.1.0 "Hello World" for [Mac 64bit](https://github.com/Shopify/minesweeper/releases/download/v0.1.0/minesweeper-0.1.0-darwin-amd64.tar.gz) or [Linux 64bit](https://github.com/Shopify/minesweeper/releases/download/v0.1.0/minesweeper-0.1.0-linux-amd64.tar.gz)
  
  3. Optional - **Grab a Google API key**
  
  Setup a Google API key by following [these intructions](https://developers.google.com/safe-browsing/lookup_guide#GettingStarted).  
  Add the key as an ENV variable e.g. `export MINESWEEPER_GOOGLE_API_KEY="<YOUR_KEY>"`

  4. Optional - **Install Suricata**
  
  Instructions and sample config coming soon.

## Usage

`$ minesweeper [options...] <url>`

Minesweeper will browse the URL, perform a security analysis and produce a verdict.

A JSON report is returned if the verdict is `suspicious`. Nothing is returned if it's `ok`.

A `suspicious` verdict means that a module has produced a positive (blacklist) `hit` or (IDS) `alert`.

Currently, there are 3 modules: [`malwaredomains`](blacklist/malwaredomains.go), [`google`](blacklist/google.go) and [`suricata`](ids/suricata.go).

## Example

```
$ minesweeper ianfette.org
 {
  "Url": "http://ianfette.org",
  "CreatedAt": "Wed Sep  3 22:27:40 UTC 2014",
  "RunDir": "/var/folders/dg/m668qw1x3szdyhmt8qs0qq3w0000gn/T/minesweeper458550870",
  "Resources": [
    {
      "Method": "GET",
      "Url": "http://ianfette.org/",
      "Status": 200,
      "ContentType": "text/html",
      "ContentLength": 43,
      "MinesweeperSha256": "0e7d00142cf0f74c7e4d5b2469c016bd421837ce692cd6a276fce2f3d5fc3a06",
      "MinesweeperSniffedMime": "text/html; charset=utf-8",
      "MinesweeperHostAddr": "173.201.140.128"
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
  "Alerts": null,
  "Verdict": "suspicious"
}
```


## How does it work?

**Minesweeper scans websites using [PhantomJS](http://phantomjs.org/) through a local MITM proxy**

* It records:
  * HTTP requests for resources such as Javascript and CSS files
    * URL, Method, Status, Content-Type
    * A sha256 sum for a file - useful for submitting to [VirusTotal](https://www.virustotal.com/)
    * A MIME-sniffed Content-Type determined using [DetectContentType](http://golang.org/pkg/net/http/#DetectContentType)
  * Javascript calls to `document.write()`
    * The HTML to be written is recorded
    * A stack trace is captured to attribute this back to an exact line in the source!
  * Javascript [DOMSubtreeModified](http://www.w3.org/TR/DOM-Level-3-Events/#event-type-DOMSubtreeModified) Mutation Events where the target is either HTMLScriptElement or HTMLIFrameElement
    * The outer HTML of the modification is recorded
* You can configure:
  * User-Agent - check out [useragentstring.com](http://www.useragentstring.com/) to build your own
  * Set an amount of milliseconds to wait for subsequent Javascript requests after the initial load
  * Lots more, `minesweeper -h`

**It captures the traffic between PhantomJS and the local MITM proxy**
* Capturing here means that the IDS has a chance to alert on HTTP request content that will never be seen in a non-proxied environment e.g. a ```<script>``` tag referencing a malicious domain that has been DNS blacklisted.
* In order to enable parallel scans, a separate proxy is setup for each scan.
  * Free ports to listen on are chosen by the operating system by binding to port 0
* By running with a BPF filter for a specific port, we can capture the traffic of each scan separately.

**It grabs any alerts from the [Suricata](http://suricata-ids.org/) IDS which is listening on localhost**
* Alerts written in the fast format are supported /var/log/suricata/fast.log
* Minesweeper also greps through the rules files (/etc/suricata/rules/*.rules) to find the full rule text and adds this to each alert

**It also checks all URLs browsed against domain blacklists**
  * Currently, there are 2 blacklists:
      * ```google``` - [Google Safe Browsing Lookup API](https://developers.google.com/safe-browsing/lookup_guide)
      * ```malwaredomains``` - [malwaredomains.com](http://www.malwaredomains.com/)

**It produces a [JSON](http://en.wikipedia.org/wiki/JSON) report**
* If there are IDS alerts or Blacklist hits, the website is deemed ```suspicious```, otherwise it's ```ok```.


## Questions

Please contact [falsenegative](https://github.com/falsenegative)
