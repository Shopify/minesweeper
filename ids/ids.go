package ids

import (
	"fmt"
	"os"
	"time"
)

type Ids interface {
	Name() (name string)
	Init() (err error)
	Check(startTime time.Time, endTime time.Time, proxyPort string) (alerts []Alert)
}

type Alert struct {
	IdsName string
	Sid     string
	Raw     string
	Rule    string
}

func Init() (idss []Ids) {
	var loadIdss []Ids

	loadIdss = append(loadIdss, new(Suricata))

	for _, ids := range loadIdss {
		err := ids.Init()
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING [init] %s\n ", err)
			continue
		}

		idss = append(idss, ids)
	}

	return idss
}

func Check(idss []Ids, startTime time.Time, endTime time.Time, proxyPort string) (alerts []Alert) {
	for _, ids := range idss {
		alerts = append(alerts, ids.Check(startTime, endTime, proxyPort)...)
	}

	return alerts
}
