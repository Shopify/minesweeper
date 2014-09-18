package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/pcap"
	"code.google.com/p/gopacket/pcapgo"
	"github.com/elazarl/goproxy"

	"github.com/Shopify/minesweeper/blacklist"
	"github.com/Shopify/minesweeper/ids"
	"github.com/Shopify/minesweeper/phantom"
)

type MinesweeperOptions struct {
	DefaultDir string
	KeepRunDir bool
	Pcap       bool
	Modules    string
	UserAgent  string
	Verbose    bool
	WaitAround int
}

type MinesweeperReport struct {
	Url       string
	CreatedAt string
	RunDir    string
	Resources []MinesweeperReportResource
	Changes   []MinesweeperReportChange
	Hits      []blacklist.Hit
	Alerts    []ids.Alert
	Verdict   string
}

type MinesweeperReportResource struct {
	Method                 string
	Url                    string
	Status                 int
	ContentType            string
	ContentLength          int
	MinesweeperSha256      string `json:",omitempty"`
	MinesweeperSniffedMime string `json:",omitempty"`
	MinesweeperHostAddr    string `json:",omitempty"`
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

func startLoProxy() string {
	proxy := goproxy.NewProxyHttpServer()

	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp == nil {
			return resp
		}

		if resp.Request != nil && len(resp.Request.Host) > 0 {
			host := resp.Request.Host
			port := ""
			if strings.Contains(host, ":") {
				h, p, err := net.SplitHostPort(resp.Request.Host)
				checkErr(err, "get remote ip split host port")
				host = h
				port = p
			}

			addrs, err := net.LookupHost(host)
			checkErr(err, "get remote ip lookup host")

			hostAddr := addrs[0]
			if len(port) > 0 {
				hostAddr = hostAddr + ":" + port
			}

			resp.Header.Add("Minesweeper-Host-Addr", hostAddr)
		}

		b, err := ioutil.ReadAll(resp.Body)
		checkErr(err, "read http response body")

		h256 := sha256.Sum256(b)
		hexOfSha256 := hex.EncodeToString(h256[:])
		resp.Header.Add("Minesweeper-Sha256", hexOfSha256)

		sniffedMime := http.DetectContentType(b)
		resp.Header.Add("Minesweeper-Sniffed-Mime", sniffedMime)

		resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))

		return resp
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	checkErr(err, "proxy listen")

	_, port, err := net.SplitHostPort(ln.Addr().String())
	checkErr(err, "proxy split host port")

	go http.Serve(ln, proxy)

	return port
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

func Minesweeper(rawurl string, options *MinesweeperOptions) (bool, string) {
	report := MinesweeperReport{}

	createdAt := time.Now().UTC()

	u, err := url.Parse(rawurl)
	checkErr(err, "parse url")

	_, err = net.LookupHost(u.Host)
	checkErr(err, "lookup host")

	runDir, err := ioutil.TempDir(options.DefaultDir, "minesweeper")
	checkErr(err, "create temp dir")

	urlForFname := regexp.MustCompile("[^a-zA-Z0-9]").ReplaceAllString(u.String(), "_")
	minesweeperFileName := filepath.Join(runDir, "minesweeper_"+createdAt.Format("20060102150405")+"_"+urlForFname)

	_, cacheDir := createBaseAndCacheDirs()

	bls := blacklist.Init(cacheDir, options.Modules)
	idss := ids.Init(options.Modules)

	proxyPort := startLoProxy()

	if options.Pcap {
		sniffLoDumpPcap(minesweeperFileName+".pcap", "tcp port "+proxyPort)
	}

	phantomScript := filepath.Join(runDir, "minesweeper.js")
	err = ioutil.WriteFile(phantomScript, []byte(phantom.Script()), 0644)
	checkErr(err, "write phantom script to base dir")

	startTime := time.Now().UTC()
	args := []string{"--load-images=no", "--ignore-ssl-errors=yes", "--web-security=no", "--proxy=127.0.0.1:" + proxyPort, phantomScript, rawurl, options.UserAgent, strconv.Itoa(options.WaitAround)}
	out, err := exec.Command("phantomjs", args...).Output()
	checkErr(err, "exec phantomjs")
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
			checkErr(err, "json unmarshal resource")
			report.Resources = append(report.Resources, resource)

			urls = append(urls, resource.Url)
		}

		if bytes.HasPrefix(line, []byte("CHANGE ")) {
			jsonChange := line[bytes.Index(line, []byte(" "))+1:]
			change := MinesweeperReportChange{}
			err := json.Unmarshal(jsonChange, &change)
			if err != nil {
				fmt.Println(string(rawurl))
				fmt.Println(string(rawurl) + " " + string(line))
				os.Exit(2)
			}
			//checkErr(err, "json unmarshal change")
			report.Changes = append(report.Changes, change)
		}
	}

	report.Hits = blacklist.Check(bls, urls)
	report.Alerts = ids.Check(idss, startTime, endTime, proxyPort)

	ok := true
	report.Verdict = "ok"
	if len(report.Hits)+len(report.Alerts) > 0 {
		report.Verdict = "suspicious"
		ok = false
	}

	b, err := json.MarshalIndent(report, "", "  ")
	checkErr(err, "json marshal report")
	b = bytes.Replace(b, []byte("\\u003c"), []byte("<"), -1)
	b = bytes.Replace(b, []byte("\\u003e"), []byte(">"), -1)
	b = bytes.Replace(b, []byte("\\u0026"), []byte("&"), -1)
	jsonReport := string(b)

	err = ioutil.WriteFile(minesweeperFileName+".json", []byte(jsonReport), 0644)
	checkErr(err, "write json report to file")

	if !options.KeepRunDir {
		err = os.RemoveAll(runDir)
		checkErr(err, "remove run dir")
	}

	return ok, jsonReport
}

func parseArgs() (string, *MinesweeperOptions) {
	var options = new(MinesweeperOptions)

	flag.StringVar(&options.DefaultDir, "d", "", "Specify the directory to hold the Runtime Directory (RunDir). Passed as first arg to osutil.Tempdir)")
	flag.BoolVar(&options.KeepRunDir, "k", false, "Keep RunDir. Do not automatically remove the directory.")
	flag.StringVar(&options.Modules, "m", "google,malwaredomains,suricata", "Specify what modules to run")
	flag.StringVar(&options.UserAgent, "u", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.94 Safari/537.36", "User-Agent")
	flag.BoolVar(&options.Verbose, "v", false, "Verbose - always show the JSON report, rather than just on suspicious verdicts")
	flag.BoolVar(&options.Pcap, "p", false, "Capture and dump traffic to a PCAP file in RunDir")
	flag.IntVar(&options.WaitAround, "z", 100, "Wait around (ms) for Javascript to exec after page load")

	flag.Usage = func() {
		fmt.Println("Usage: minesweeper [options...] <url>")
		fmt.Println("Options:")
		flag.PrintDefaults()
	}

	flag.Parse()

	rawurl := flag.Arg(0)
	if len(rawurl) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	rawurl = strings.ToLower(rawurl)
	if !strings.HasPrefix(rawurl, "http") {
		rawurl = "http://" + rawurl
	}
	if strings.Contains(rawurl, "127.0.0.1") || strings.Contains(rawurl, "localhost") {
		fmt.Println("Sorry, you can't directly use localhost as it prevents proxying. A workaround is to create an entry in you hosts file.")
		os.Exit(2)
	}

	return rawurl, options
}

func main() {
	rawurl, options := parseArgs()

	ok, report := Minesweeper(rawurl, options)

	if !ok || options.Verbose {
		fmt.Printf("%s\n", report)
	}

	if !ok {
		os.Exit(1)
	}
}
