package ids

import (
	"bufio"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

type Suricata struct {
	Ids
	AlertsFile  string
	RulesDir    string
	AlertRegexp *regexp.Regexp
}

func (i *Suricata) Name() string {
	return "Suricata"
}

func (i *Suricata) Init(cacheDir string) {
	i.AlertsFile = "/var/log/suricata/fast.log"
	i.RulesDir = "/etc/suricata/rules"

	i.AlertRegexp, _ = regexp.Compile(`^(\d{2}\/\d{2}\/\d{4}-\d{2}:\d{2}:\d{2})\.(\d{6})  \[\*\*\] \[(\d+):(\d+):(\d+)\] (.+?) \[\*\*\] \[Classification: (.+?)\] \[Priority: (\d+)\] \{(.+?)\} ((?:[0-9]{1,3}\.){3}[0-9]{1,3}):(\d+) -> ((?:[0-9]{1,3}\.){3}[0-9]{1,3}):(\d+)$`)
}

func (i *Suricata) Update() {
}

func (i *Suricata) Check(startTime time.Time, endTime time.Time, proxyPort string) []Alert {
	var alerts []Alert

	f, err := os.Open(i.AlertsFile)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		matches := i.AlertRegexp.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		datetime := matches[1]
		//usec := matches[2]
		//gid := matches[3]
		sid := matches[4]
		//rev := matches[5]
		//msg := matches[6]
		//class := matches[7]
		//priority := matches[8]
		//proto := matches[9]
		//srcIp := matches[10]
		srcPort := matches[11]
		//dstIp := matches[12]
		dstPort := matches[13]

		if srcPort != proxyPort && dstPort != proxyPort {
			continue
		}

		alertTime, _ := time.Parse("01/02/2006-15:04:05", datetime)
		if alertTime.Before(startTime) || alertTime.After(endTime) {
			continue
		}

		alert := Alert{}
		alert.IdsName = i.Name()
		alert.Sid = sid
		alert.Raw = line
		alert.Rule = findRule(i.RulesDir, alert.Sid)
		alerts = append(alerts, alert)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return alerts
}

func findRule(rulesDir string, sid string) string {
	var sidRegexp = regexp.MustCompile("sid:" + sid)
	var rule string

	rulesFiles, _ := filepath.Glob(rulesDir + "/*.rules")
	for _, rulesFile := range rulesFiles {
		f, err := os.Open(rulesFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()

			if sidRegexp.MatchString(line) {
				rule = line
				break
			}
		}

		if len(rule) > 0 {
			break
		}
	}

	return rule
}
