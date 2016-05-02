package blacklist

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type Google struct {
	Blacklist
	url string
}

func (bl *Google) Name() (name string) {
	return "google"
}

func (bl *Google) Init(cacheDir string) (err error) {
	client := "minesweeper"
	appVer := "0.1"
	pVer := "3.0"

	keyEnv := "MINESWEEPER_GOOGLE_API_KEY"
	key := os.Getenv(keyEnv)
	if len(key) == 0 {
		return errors.New(keyEnv + " environment variable not set")
	}

	bl.url = fmt.Sprintf("https://sb-ssl.google.com/safebrowsing/api/lookup?client=%s&key=%s&appver=%s&pver=%s", client, key, appVer, pVer)

	return nil
}

func (bl *Google) Check(urls []string) (hits []Hit) {
	max := 500
	a := 0
	for i, _ := range urls {
		if (i+1)%max == 0 || (i+1) == len(urls) {
			num := len(urls[a : i+1])

			postBody := fmt.Sprintf("%d\n%s", num, strings.Join(urls[a:i+1], "\n"))

			resp, err := http.Post(bl.url, "multipart/form-data", strings.NewReader(postBody))
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR [google post] %s\n ", err)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode == 204 {
				return
			}
			if resp.StatusCode != 200 {
				fmt.Fprintf(os.Stderr, "ERROR [google post !200] %s\n ", resp.Status)
				return
			}

			body, err := ioutil.ReadAll(resp.Body)
			for j, verdict := range bytes.Split(body, []byte("\n")) {
				if string(verdict) != "ok" {
					malwareUrl := strings.Join(urls[a+j:a+j+1], "")
					u, err := url.Parse(malwareUrl)
					if err != nil {
						fmt.Fprintf(os.Stderr, "ERROR [google malware url parse] %s\n ", err)
						return
					}
					hit := Hit{bl.Name(), malwareUrl, u.Host, string(verdict), "https://developers.google.com/safe-browsing/developers_guide_v3"}
					hits = append(hits, hit)
				}
			}

			a = i + 1
		}
	}

	return hits
}
