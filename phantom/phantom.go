package phantom

func Script() string {
  return phantomScript
}

const phantomScript =
`var page = require('webpage').create()
page.resources = [];

// standard error handler
phantom.onError = function(msg, trace) {
  console.log(msg);
  phantom.exit(1);
};

// required to console.log during evaluate
page.onConsoleMessage = function(msg){
  console.log(msg);
};

// record resource errors
page.onResourceError = function(resourceError) {
  page.resources.forEach(function (resource) {
    if (resource.request.url === resourceError.url) {
      resource.error = resourceError.errorString;
    }
  });   
};

// record resource timeouts
page.onResourceTimeout = function(e) {
  page.resources.forEach(function (resource) {
    if (resource.request.url === e.url) {
      resource.error = "ResourceTimeout " + e.errorString;
    }
  });   
};

// callback for each network request, save for later processing
page.onResourceRequested = function (req) {
    page.resources[req.id] = {
        request: req,
        startReply: null,
        endReply: null
    };
};

// callback for each network reply, save for later processing
page.onResourceReceived = function (res) {
    if (res.stage === 'start') {
      page.resources[res.id].startReply = res;
    }
    if (res.stage === 'end') {
      if( page.resources[res.id].startReply == null ) {
        page.resources[res.id].startReply = res;
      }
      page.resources[res.id].endReply = res;
    }
};

// callback after page created but before url is loaded, used to inject our JS overrides and listeners
page.onInitialized = function() {
  page.evaluate(function () {
    document.write = function(s) {
      HTMLDocument.prototype.write.apply(this, arguments);

      try {
        throw new Error();
      } catch(e) {
        var trace_list = e.stack.split("    at ");
        trace_list.shift();
        trace_list.shift();
        for (var i = 0; i < trace_list.length; i++) {
          trace_list[i] = trace_list[i].replace(/^\s+|\s+$/g, '');
        }
        var trace = trace_list.toString();

        var change = {};
        change.Type = "document.write";
        change.Content = s;
        change.Context = trace;
        console.log("CHANGE " + JSON.stringify(change));
      }
    }
    
    document.addEventListener("DOMSubtreeModified", function(e) {
      var elementTypes = ["HTMLScriptElement", "HTMLIFrameElement"];
      var targetType = Object.prototype.toString.call(e.target).slice(8, -1);

      if (elementTypes.indexOf(targetType) !== -1) {
        var change = {};
        change.Type = "DOMSubtreeModified";
        change.Content = e.target.outerHTML; //outerHTML(e.target);
        change.Context = null;
        console.log("CHANGE " + JSON.stringify(change));
      }
    }, false);
  });
};

// set defaults
var waitAround = 100; // milliseconds 

// read command line args
var args = require('system').args;
if (args.length < 2) {
  console.log('Please specify a URL.');
  phantom.exit(1);
}
var url = args[1];
if (args.length >= 3) { 
  page.settings.userAgent = args[2];
}
if (args.length >= 4) { 
  waitAround = args[3];
}

// open page
page.open(url, function (status) {
  if (status !== "success") {
    console.log("Couldn't open " + url);
    phantom.exit(1);
  }
  
  // wait for js to execute 
  window.setTimeout(function () {
    printResources();
    phantom.exit();
  }, waitAround);
});

// generare resources by matching requests/replies and parsing custom headers
printResources = function() {
  page.resources.forEach(function (resource) {
    if (resource.request.url.match(/^data:/i)) {
      return;
    }
    
    var r = {
      "Method": resource.request.method,
      "Url": resource.request.url,
      "ContentType": null,
      "ContentLength": resource.startReply ? resource.startReply.bodySize : null,
      "Status": resource.endReply ? resource.endReply.status : null,
      "MinesweeperSha256": null,
      "MinesweeperSniffedMime": null,
      "MinesweeperHostAddr": null,
      "Error": resource.error ? resource.error : null
    };

    if (resource.startReply) {
      resource.startReply.headers.forEach(function(h) {
        if (h.name === "Content-Length") {
          r["ContentLength"] = Number(h.value);
        }

        // check for custom reply headers added by proxy
        var customHeaders = ["Minesweeper-Sha256", "Minesweeper-Host-Addr", "Minesweeper-Sniffed-Mime"];
        if (customHeaders.indexOf(h.name) !== -1) {
          var key = h.name.replace(/-/g, '');
          r[key] = h.value;
        }
      });
    }
    
    if (resource.endReply) {
      if (resource.endReply.contentType) {
        var contentType = resource.endReply.contentType;
        if (contentType.indexOf(";") != -1) {
          contentType = contentType.substring(0, contentType.indexOf(";"));
        }
        r["ContentType"] = contentType;
      }
    }
    
    console.log("RESOURCE " + JSON.stringify(r));
  });
}`
