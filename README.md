minesweeper
===========

## Install

1. **Install PhantomJS**

  On Mac  
  `brew install phantomjs`  
  On Ubuntu  
  `apt-get install phantomjs`  
  Binary Install  
  ``http://phantomjs.org/download.html``

2. **Install the minesweeper binary**

  Download [Release v0.1.0 "Hello World"](https://github.com/Shopify/minesweeper/releases/download/v0.1.0/minesweeper)

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

## Questions

Please contact martin.charlesworth@shopify.com
