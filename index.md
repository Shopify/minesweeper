---
layout: index
---

## Description

Minesweeper is a tool to detect websites infected with drive-by malware.

Shopify uses Minesweeper to protect its 100,000+ online stores from web-based malware infections.

Minesweeper deals with not only the problem of detecting the malware, but also attributing an infection back to a particular asset. It is designed for high speed, parallel operation.

## Usage

    Usage: minesweeper [options...] <url>
    Options:
      -d="": Specify the directory to hold the Runtime Directory (RunDir). Passed as first arg to osutil.Tempdir)
      -k=false: Keep RunDir. Do not automatically remove the directory.
      -p=false: Capture and dump traffic to a PCAP file in RunDir
      -u="Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:31.0) Gecko/20100101 Firefox/31.0": User-Agent
      -v=false: Verbose - always show the JSON report, rather than just on suspicious verdicts
      -z=100: Wait around (ms) for Javascript to exec after page load

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

## License

Copyright (c) 2012 Shopify. Released under the [MIT-LICENSE](http://opensource.org/licenses/MIT).
