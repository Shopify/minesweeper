package blacklist

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Blacklist interface {
	Name() (name string)
	Init(cacheDir string) (err error)
	Check(urls []string) (hits []Hit)
}

type Hit struct {
	BlacklistName string
	Url           string
	Domain        string
	Type          string
	Ref           string
}

func Init(cacheDir string) (bls []Blacklist) {
	var loadBls []Blacklist

	loadBls = append(loadBls, new(Malwaredomains))
	loadBls = append(loadBls, new(Google))

	for _, bl := range loadBls {
		blCacheDir := filepath.Join(cacheDir, bl.Name())
		os.MkdirAll(blCacheDir, 0755)

		err := bl.Init(blCacheDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR [init] %s\n", err)
			continue
		}

		bls = append(bls, bl)
	}

	return bls
}

func Check(bls []Blacklist, urls []string) (hits []Hit) {
	for _, bl := range bls {
		hits = append(hits, bl.Check(urls)...)
	}

	return hits
}

func CacheGet(cacheDir string, rawurl string, hours int) (file string, err error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return "", err
	}

	file = filepath.Join(cacheDir, strings.Replace(u.Path, "/", "_", -1))

	if !cached(file, hours) {
		out, err := ioutil.TempFile("", "minesweeper")
		if err != nil {
			return "", err
		}
		defer os.Remove(out.Name())

		resp, err := http.Get(u.String())
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		io.Copy(out, resp.Body)

		err = os.Rename(out.Name(), file)
		if err != nil {
			return "", err
		}
	}

	return file, nil
}

func cached(file string, hours int) bool {
	info, err := os.Stat(file)
	if err != nil {
		return false
	} else {
		if int(time.Since(info.ModTime()).Hours()) >= hours {
			return false
		}
	}

	return true
}
