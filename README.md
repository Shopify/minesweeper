minesweeper
===========

Minesweeper is a Go tool to detect websites that have been infected with malware.

## Install

  1. **Install PhantomJS**
  
  On Mac  
  `brew install phantomjs`  
  On Ubuntu  
  `apt-get install phantomjs`  
  Binary Install  
  ``http://phantomjs.org/download.html``
  
  2. **Install minesweeper**
  
  Download binary for Mac, 64-bit [Release v0.1.0 "Hello World"](https://github.com/Shopify/minesweeper/releases/download/v0.1.0/minesweeper-0.1.0-darwin-amd64.tar.zip)

## Usage

```
Usage: minesweeper [options...] <url>
Options:
  -d="": Specify the directory to hold the Runtime Directory (RunDir). Passed as first arg to osutil.Tempdir)
  -k=false: Keep RunDir. Do not automatically remove the directory.
  -p=false: Capture and dump traffic to a PCAP file in RunDir
  -u="Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:31.0) Gecko/20100101 Firefox/31.0": User-Agent
  -v=false: Verbose - always show the JSON report, rather than just on suspicious verdicts
  -z=100: Wait around (ms) for Javascript to exec after page load
```

## How does it work?

**Minesweeper scans websites using [PhantomJS](http://phantomjs.org/) through a local MITM proxy**

* It records:
  * HTTP requests for resources such as Javascript and CSS files
    * URL, Method, Status, Content-Type
    * A sha256 sum for a file - useful for submitting to [VirusTotal](https://www.virustotal.com/)
    * A decompressed file size in bytes - it also attempts to turn off compression by setting Accept-Encoding: none
    * A MIME file type determined using [python-magic](https://github.com/ahupp/python-magic), a libmagic wrapper
  * Javascript calls to `document.write()`
    * The HTML to be written is recorded
    * A stack trace is captured to attribute this back to it's source
  * Javascript [DOMSubtreeModified](http://www.w3.org/TR/DOM-Level-3-Events/#event-type-DOMSubtreeModified) Mutation Events where the target is either HTMLScriptElement or HTMLIFrameElement
    * The outer HTML of the modification is recorded
* You can configure: (see options section below)
  * User-Agent - check out [useragentstring.com](http://www.useragentstring.com/) to build your own
  * Set an amount of milliseconds to wait for subsequent javascript requests after the initial load

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
* If there are any IDS alerts or Blacklist hits, the website is deemed ```suspicious```, otherwise it's ```ok```.


## Questions

Please contact martin.charlesworth@shopify.com
