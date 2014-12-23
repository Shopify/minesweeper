package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	sh "github.com/codeskyblue/go-sh"

	"github.com/Shopify/minesweeper/blacklist"
	"github.com/Shopify/minesweeper/phantom"
)

var baseDir string
var cacheDir string
var phantomScript string

var bls []blacklist.Blacklist

var dnsCache = make(map[string]string, 0)
var dnsCacheLock sync.RWMutex

type MinesweeperOptions struct {
	Binding    string
	Expiry     int
	Modules    string
	Port       string
	UserAgent  string
	Workers    int
	WaitAround int
}

var options = new(MinesweeperOptions)

type MinesweeperReport struct {
	Id        string
	Url       string
	Verdict   string
	Error     string `json:",omitempty"`
	CreatedAt string
	Resources []MinesweeperReportResource
	Changes   []MinesweeperReportChange
	Hits      []blacklist.Hit
}

type MinesweeperReportResource struct {
	Method        string
	Url           string
	Status        int
	ContentType   string
	ContentLength int
	Error         string `json:",omitempty"`
}

type MinesweeperReportChange struct {
	Type    string
	Content string
	Context string
}

func checkErr(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR [%s] %s\n", msg, err)
		os.Exit(1)
	}
}

func initModules() {
	bls = blacklist.Init(cacheDir, options.Modules)
}

func createBaseAndCacheDirs() {
	usr, err := user.Current()
	checkErr(err, "get current user")

	baseDir = filepath.Join(usr.HomeDir, ".minesweeper")
	os.MkdirAll(baseDir, 0755)

	cacheDir = filepath.Join(baseDir, "cache")
	os.MkdirAll(cacheDir, 0755)
}

func writePhantomScript() {
	phantomScript = filepath.Join(baseDir, "minesweeper.js")
	err := ioutil.WriteFile(phantomScript, []byte(phantom.Script()), 0644)
	checkErr(err, "write phantom script to base dir")
}

func Minesweeper(rawurl string) (report *MinesweeperReport) {
	report = &MinesweeperReport{}
	report.Url = rawurl
	report.CreatedAt = time.Now().UTC().Format(time.UnixDate)

	args := []string{"--load-images=no", "--ignore-ssl-errors=yes", "--ssl-protocol=any", "--web-security=no", phantomScript, rawurl, options.UserAgent, strconv.Itoa(options.WaitAround)}
	out, err := sh.Command("phantomjs", args).SetTimeout(time.Second * 10).Output()
	if err != nil {
		report.Verdict = "error"
		report.Error = "exec phantomjs: " + err.Error()
		return
	}

	var urls []string

	lines := bytes.Split(out, []byte("\n"))
	for _, line := range lines {
		if bytes.HasPrefix(line, []byte("RESOURCE ")) {
			jsonResource := line[bytes.Index(line, []byte(" "))+1:]
			resource := MinesweeperReportResource{}
			err := json.Unmarshal(jsonResource, &resource)
			if err != nil {
				report.Verdict = "error"
				report.Error = "json unmarshal resource: " + err.Error()
				return
			}
			report.Resources = append(report.Resources, resource)

			urls = append(urls, resource.Url)
		}

		if bytes.HasPrefix(line, []byte("CHANGE ")) {
			jsonChange := line[bytes.Index(line, []byte(" "))+1:]
			change := MinesweeperReportChange{}
			err := json.Unmarshal(jsonChange, &change)
			if err != nil {
				report.Verdict = "error"
				report.Error = "json unmarshal change: " + err.Error()
				return
			}
			report.Changes = append(report.Changes, change)
		}
	}

	report.Hits = blacklist.Check(bls, urls)

	report.Verdict = "ok"
	if len(report.Hits) > 0 {
		report.Verdict = "suspicious"
	}

	return
}

func parseArgs() {
	flag.StringVar(&options.Binding, "b", "127.0.0.1", "Binds to the specified IP")
	flag.IntVar(&options.Expiry, "e", 24, "Expire results after N hours")
	flag.StringVar(&options.Modules, "m", "google,malwaredomains", "Module run list")
	flag.StringVar(&options.Port, "p", "6463", "Runs on the specified port")
	flag.StringVar(&options.UserAgent, "u", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.65 Safari/537.36", "User-Agent")
	flag.IntVar(&options.Workers, "w", 16, "Workers")
	flag.IntVar(&options.WaitAround, "z", 100, "Zzz. Sleep for N (ms) so Javascript can exec after page load.")

	flag.Usage = func() {
		fmt.Println("Usage: minesweeper [options...]")
		fmt.Println("Options:")
		flag.PrintDefaults()
	}

	flag.Parse()
}

func resolveDomain(domain string) (string, error) {
	var host string
	var port string
	var ip string
	var ok bool
	var err error

	if strings.Contains(domain, ":") {
		host, port, err = net.SplitHostPort(domain)
		if err != nil {
			return "", err
		}
	} else {
		host = domain
	}

	if isIp := net.ParseIP(host); isIp != nil {
		return domain, nil
	}

	dnsCacheLock.RLock()
	{
		ip, ok = dnsCache[host]
	}
	dnsCacheLock.RUnlock()

	if !ok {
		ips, err := net.LookupIP(host)
		if err != nil {
			return "", err
		}

		if len(ips) == 0 {
			return "", fmt.Errorf("failed to lookup %s", host)
		}

		// If it's an ipv6 address we need brackets around it.
		if ipv4 := ips[0].To4(); ipv4 != nil {
			ip = ipv4.String()
		} else {
			ip = "[" + ips[0].String() + "]"
		}

		dnsCacheLock.Lock()
		{
			dnsCache[host] = ip
		}
		dnsCacheLock.Unlock()
	}

	if port != "" {
		return ip + ":" + port, nil
	} else {
		return ip, nil
	}
}

func cacheDial(network string, addr string) (net.Conn, error) {
	url, err := resolveDomain(addr)
	if err != nil {
		return nil, err
	}

	return net.Dial(network, url)
}

type Server struct {
	Requests chan *Request
}

type Request struct {
	Url        string
	ResultChan chan *MinesweeperReport
}

type Response struct {
	Verdict string
	Report  *MinesweeperReport `json:",omitempty"`
}

func logHttpError(req *http.Request, w http.ResponseWriter, errorMessage string, code int) {
	log.Printf("%d %s [%s %s]\n", code, errorMessage, req.Method, req.URL.String())
	http.Error(w, errorMessage, code)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	log.Println(req.Method + " " + req.URL.String())

	req.ParseForm()

	if req.URL.Path != "/scan" {
		logHttpError(req, w, "Unknown Path", http.StatusBadRequest)
		return
	}

	if req.Form["url"] == nil {
		logHttpError(req, w, "Missing URL", http.StatusBadRequest)
		return
	}

	rawurl := strings.ToLower(req.Form["url"][0])
	if !strings.HasPrefix(rawurl, "http") {
		rawurl = "http://" + rawurl
	}

	_, err := url.Parse(rawurl)
	if err != nil {
		logHttpError(req, w, "Couldn't parse URL", http.StatusBadRequest)
		return
	}

	if strings.Contains(rawurl, "127.0.0.1") || strings.Contains(rawurl, "localhost") {
		logHttpError(req, w, "Localhost prevents proxy, workaround using hosts file", http.StatusBadRequest)
		return
	}

	request := &Request{Url: rawurl, ResultChan: make(chan *MinesweeperReport)}
	s.Requests <- request
	report := <-request.ResultChan

	response := &Response{Verdict: report.Verdict}
	if report.Verdict != "ok" {
		response.Report = report
	}

	b, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		logHttpError(req, w, "Couldn't create JSON response", http.StatusInternalServerError)
		return
	}
	b = bytes.Replace(b, []byte("\\u003c"), []byte("<"), -1)
	b = bytes.Replace(b, []byte("\\u003e"), []byte(">"), -1)
	b = bytes.Replace(b, []byte("\\u0026"), []byte("&"), -1)

	log.Printf("%d %s %s [%s %s] %s\n", 200, report.Verdict, report.Id, req.Method, req.URL.String(), report.Error)
	w.Write(b)
}

func worker(requests chan *Request) {
	for request := range requests {
		report := Minesweeper(request.Url)
		request.ResultChan <- report
	}
}

func workerPool(n int) chan *Request {
	requests := make(chan *Request)

	for i := 0; i < n; i++ {
		go worker(requests)
	}

	return requests
}

func main() {
	parseArgs()
	createBaseAndCacheDirs()
	writePhantomScript()
	initModules()

	requests := workerPool(options.Workers)
	server := &Server{Requests: requests}

	listenOn := options.Binding + ":" + options.Port
	log.Printf("Listening on %s...\n", listenOn)
	log.Fatal(http.ListenAndServe(listenOn, server))
}
