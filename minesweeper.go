package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/pcap"
	"code.google.com/p/gopacket/pcapgo"
	sh "github.com/codeskyblue/go-sh"
	"github.com/elazarl/goproxy"

	"github.com/Shopify/minesweeper/blacklist"
	"github.com/Shopify/minesweeper/ids"
	"github.com/Shopify/minesweeper/phantom"
)

var dnsCache = make(map[string]string, 0)
var dnsCacheLock sync.RWMutex

type MinesweeperOptions struct {
	DefaultDir string
	KeepRunDir bool
	Pcap       bool
	Modules    string
	UserAgent  string
	Verbose    bool
	Workers    int
	WaitAround int
}

var options = new(MinesweeperOptions)

type MinesweeperReport struct {
	Url       string
	Verdict   string
	Error     string `json:",omitempty"`
	CreatedAt string
	RunDir    string
	Resources []MinesweeperReportResource
	Changes   []MinesweeperReportChange
	Hits      []blacklist.Hit
	Alerts    []ids.Alert
}

type MinesweeperReportResource struct {
	Method                 string
	Url                    string
	Status                 int
	ContentType            string
	ContentLength          int
	MinesweeperSha256      string `json:",omitempty"`
	MinesweeperSniffedMime string `json:",omitempty"`
	Error                  string `json:",omitempty"`
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

func sniffLoDumpPcap(pcapFname string, bpf string) {
	ifs, err := pcap.FindAllDevs()
	checkErr(err, "pcap findalldevs")

	localhost := "lo"
	for _, iface := range ifs {
		if strings.HasPrefix(iface.Name, "lo") {
			localhost = iface.Name
			break
		}
	}

	liveHandle, err := pcap.OpenLive(localhost, 65535, false, -1)
	checkErr(err, "pcap openlive")

	err = liveHandle.SetBPFFilter(bpf)
	checkErr(err, "pcap set bpf")

	go func() {
		f, err := os.Create(pcapFname)
		checkErr(err, "open pcap file")
		defer f.Close()

		w := pcapgo.NewWriter(f)
		w.WriteFileHeader(65536, liveHandle.LinkType())

		packetSource := gopacket.NewPacketSource(liveHandle, liveHandle.LinkType())
		for packet := range packetSource.Packets() {
			err = w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			checkErr(err, "write packet to pcap file")
		}
	}()
}

func startLoProxy() (net.Listener, *goproxy.ProxyHttpServer, string) {
	proxy := goproxy.NewProxyHttpServer()

	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp == nil {
			return resp
		}

		b, err := ioutil.ReadAll(resp.Body)
		if err == nil {
			h256 := sha256.Sum256(b)
			hexOfSha256 := hex.EncodeToString(h256[:])
			resp.Header.Add("Minesweeper-Sha256", hexOfSha256)

			sniffedMime := http.DetectContentType(b)
			resp.Header.Add("Minesweeper-Sniffed-Mime", sniffedMime)

			resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
		}

		return resp
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	checkErr(err, "proxy listen")

	_, port, err := net.SplitHostPort(ln.Addr().String())
	checkErr(err, "proxy split host port")

	s := &http.Server{
		Handler: proxy,
	}
	go s.Serve(ln)

	return ln, proxy, port
}

func createBaseAndCacheDirs() (string, string) {
	usr, err := user.Current()
	checkErr(err, "get current user")

	baseDir := filepath.Join(usr.HomeDir, ".minesweeper")
	os.MkdirAll(baseDir, 0755)

	cacheDir := filepath.Join(baseDir, "cache")
	os.MkdirAll(cacheDir, 0755)

	return baseDir, cacheDir
}

func Minesweeper(rawurl string) (report *MinesweeperReport) {
	createdAt := time.Now().UTC()
	report = &MinesweeperReport{}

	ln, proxy, proxyPort := startLoProxy()
	proxy.Tr.DisableCompression = false
	proxy.Tr.MaxIdleConnsPerHost = 64
	proxy.Tr.Dial = cacheDial

	runDir, err := ioutil.TempDir(options.DefaultDir, "minesweeper")
	checkErr(err, "create temp dir")

	urlForFname := regexp.MustCompile("[^a-zA-Z0-9]").ReplaceAllString(rawurl, "_")
	minesweeperFileName := filepath.Join(runDir, "minesweeper_"+createdAt.Format("20060102150405")+"_"+urlForFname)

	_, cacheDir := createBaseAndCacheDirs()

	bls := blacklist.Init(cacheDir, options.Modules)
	idss := ids.Init(options.Modules)

	if options.Pcap {
		sniffLoDumpPcap(minesweeperFileName+".pcap", "tcp port "+proxyPort)
	}

	phantomScript := filepath.Join(runDir, "minesweeper.js")
	err = ioutil.WriteFile(phantomScript, []byte(phantom.Script()), 0644)
	checkErr(err, "write phantom script to base dir")

	args := []string{"--load-images=no", "--ignore-ssl-errors=yes", "--web-security=no", "--proxy=127.0.0.1:" + proxyPort, phantomScript, rawurl, options.UserAgent, strconv.Itoa(options.WaitAround)}

	startTime := time.Now().UTC()
	out, err := sh.Command("phantomjs", args).SetTimeout(time.Second * 10).Output()
	if err != nil {
		report.Verdict = "error"
		report.Error = "exec phantomjs: " + err.Error()
		return
	}
	endTime := time.Now().UTC()

	report.CreatedAt = createdAt.Format(time.UnixDate)
	report.RunDir = runDir
	report.Url = rawurl

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
	report.Alerts = ids.Check(idss, startTime, endTime, proxyPort)

	report.Verdict = "ok"
	if len(report.Hits)+len(report.Alerts) > 0 {
		report.Verdict = "suspicious"
	}

	b, err := json.MarshalIndent(report, "", "  ")
	checkErr(err, "json marshal report")
	b = bytes.Replace(b, []byte("\\u003c"), []byte("<"), -1)
	b = bytes.Replace(b, []byte("\\u003e"), []byte(">"), -1)
	b = bytes.Replace(b, []byte("\\u0026"), []byte("&"), -1)
	jsonReport := string(b)

	err = ioutil.WriteFile(minesweeperFileName+"."+report.Verdict+".json", []byte(jsonReport), 0644)
	checkErr(err, "write json report to file")

	if !options.KeepRunDir {
		err = os.RemoveAll(runDir)
		checkErr(err, "remove run dir")
	}

	proxy.Tr.CloseIdleConnections()
	ln.Close()

	return
}

func parseArgs() {
	flag.StringVar(&options.DefaultDir, "d", "", "Specify the directory to hold the Runtime Directory (RunDir). Passed as first arg to osutil.Tempdir.")
	flag.BoolVar(&options.KeepRunDir, "k", false, "Keep RunDir. Do not automatically remove the directory.")
	flag.StringVar(&options.Modules, "m", "google,malwaredomains,suricata", "Specify what modules to run.")
	flag.StringVar(&options.UserAgent, "u", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.94 Safari/537.36", "User-Agent")
	flag.BoolVar(&options.Verbose, "v", false, "Verbose - always show the JSON report, rather than just on suspicious verdicts.")
	flag.BoolVar(&options.Pcap, "p", false, "Capture and dump traffic to a PCAP file in RunDir.")
	flag.IntVar(&options.Workers, "w", 16, "The number of URLs to (attempt to) scan in parallel.")
	flag.IntVar(&options.WaitAround, "z", 100, "Wait around (ms) for Javascript to exec after page load.")

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

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()

	if req.Form["url"] == nil {
		http.Error(w, "Missing URL", http.StatusBadRequest)
		return
	}

	rawurl := strings.ToLower(req.Form["url"][0])
	if !strings.HasPrefix(rawurl, "http") {
		rawurl = "http://" + rawurl
	}

	_, err := url.Parse(rawurl)
	if err != nil {
		http.Error(w, "Couldn't parse URL", http.StatusBadRequest)
		return
	}

	if strings.Contains(rawurl, "127.0.0.1") || strings.Contains(rawurl, "localhost") {
		http.Error(w, "Localhost prevents proxy, workaround using hosts file", http.StatusBadRequest)
		return
	}

	request := &Request{Url: rawurl, ResultChan: make(chan *MinesweeperReport)}
	s.Requests <- request
	report := <-request.ResultChan

	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		http.Error(w, "Couldn't create JSON response", http.StatusInternalServerError)
		return
	}
	b = bytes.Replace(b, []byte("\\u003c"), []byte("<"), -1)
	b = bytes.Replace(b, []byte("\\u003e"), []byte(">"), -1)
	b = bytes.Replace(b, []byte("\\u0026"), []byte("&"), -1)

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

	requests := workerPool(options.Workers)
	server := &Server{Requests: requests}

	log.Println("Listening on 0.0.0.0:6463...")
	log.Fatal(http.ListenAndServe(":6463", server))
}
