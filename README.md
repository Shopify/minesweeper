minesweeper
===========

Minesweeper scans websites to detect drive-by malware.

[Install](#install)  
[Test](#test)  
[How it works](#howitworks)  
[Questions](#questions)  

----------------------------------------------------

## <a name="install"></a> Install

This guide is for Ubuntu Server 14.04 LTS "Trusty Tahr", non-root user with sudo privilege.

### Server config

Add a user to run minesweeper
```
sudo adduser --system minesweeper
```

### PhantomJS

Install phantomjs
```
sudo apt-get install phantomjs
```

### Google

Grab a Google API key, you'll need it soon  
https://developers.google.com/safe-browsing/lookup_guide#GettingStarted

### Minesweeper

Download
```
wget https://github.com/Shopify/minesweeper/releases/download/0.3.1/minesweeper-0.3.1-linux-amd64.tar.gz
```

Extract and cd
```
tar xzf minesweeper-0.3.1-linux-amd64.tar.gz
cd minesweeper-0.3.1-linux-amd64
```

Install binary
```
sudo cp minesweeper /usr/local/bin/
```

Add Google API key to upstart script
```
vim minesweeper.conf
> env MINESWEEPER_GOOGLE_API_KEY=your_google_api_key
```

Install upstart script
```
sudo cp minesweeper.conf /etc/init/
```

Start minesweeper
```
sudo service minesweeper start
```

Minesweeper should now be listening on `127.0.0.1:6463`, logging to `/var/log/minesweeper.log`.

### Nginx

Install nginx as a reverse proxy so that we don't have to run minesweeper as root
```
sudo apt-get install nginx
```

Configure nginx to proxy requests to minesweeper
```
sudo vim /etc/nginx/sites-enabled/default
> server_name your_ip_or_hostname
>
> location / {
>   proxy_set_header X-Real-IP $remote_addr;
>   proxy_set_header X-Forwarded-For $remote_addr;
>   proxy_set_header Host $host;
>   proxy_pass http://127.0.0.1:6463;
> }
```

Restart nginx
```
sudo service nginx restart
```

----------------------------------------------------

## <a name="test"></a> Test

```
$ curl http://localhost/scan?url=ianfette.org
{
  "Verdict": "suspicious",
  "Report": {
    "Id": "",
    "Url": "http://ianfette.org",
    "Verdict": "suspicious",
    "CreatedAt": "Tue Dec 23 19:16:27 UTC 2014",
    "Resources": [
      {
        "Method": "GET",
        "Url": "http://ianfette.org/",
        "Status": 200,
        "ContentType": "text/html",
        "ContentLength": 43
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
    ]
  }
}
```

----------------------------------------------------

## <a name="howitworks"></a> How it works

Minesweeper will scan a URL, perform a security analysis and say it's `suspicious` or `ok`.

A `suspicious` verdict means that a module has produced a positive (blacklist) `hit`.

Currently, there are 2 modules: [`malwaredomains`](blacklist/malwaredomains.go), [`google`](blacklist/google.go).

**Minesweeper scans websites using [PhantomJS](http://phantomjs.org/)**

* It records:
  * HTTP requests for resources such as Javascript and CSS files
    * URL, Method, Status, Content-Type
  * Javascript calls to `document.write()`
    * The HTML to be written is recorded
    * A stack trace is captured to attribute this back to an exact line in the source!
  * Javascript [DOMSubtreeModified](http://www.w3.org/TR/DOM-Level-3-Events/#event-type-DOMSubtreeModified) Mutation Events where the target is either `HTMLScriptElement` or `HTMLIFrameElement`
    * The outer HTML of the modification is recorded

**It also checks all URLs browsed against domain blacklists**
  * Currently, there are 2 blacklists:
      * ```google``` - [Google Safe Browsing Lookup API](https://developers.google.com/safe-browsing/lookup_guide)
      * ```malwaredomains``` - [malwaredomains.com](http://www.malwaredomains.com/)

**It produces a JSON report**
* If there are Blacklist hits, the website is deemed `suspicious`, otherwise it's `ok`.

----------------------------------------------------

## <a name="questions"></a> Questions

Don't suffer, just ask! [falsenegative](https://github.com/falsenegative)
