package ids

import (
	"time"
)

type Ids interface {
	Name() string
	Init(cacheDir string)
	Check(startTime time.Time, endTime time.Time, proxyPort string) []Alert
}

type Alert struct {
	IdsName string
	Sid     string
	Raw     string
	Rule    string
}

func Init(cacheDir string) []Ids {
	var idss []Ids

	idss = append(idss, new(Suricata))

	for _, ids := range idss {
		ids.Init(cacheDir)
	}

	return idss
}

func Check(idss []Ids, startTime time.Time, endTime time.Time, proxyPort string) []Alert {
	var alerts []Alert

	for _, ids := range idss {
		alerts = append(alerts, ids.Check(startTime, endTime, proxyPort)...)
	}

	return alerts
}
