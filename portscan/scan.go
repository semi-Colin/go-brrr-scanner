package portscan

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Scan struct {
	ScanType     string
	Address      string
	Port         PortData
	delayEnabled bool
	delayTime    time.Duration
	ThreadCount  int
}

type PortData struct {
	Format int //indicator for combo(3), range (2), or list (1)
	List   []int
	Min    int
	Max    int
	Total  int
}

type ScanResult struct {
	Port     int
	State    string
	Protocol string
	Service  string
}

// Implements sort.Interface to allow for sorting of results
type ScanResSort []ScanResult

func (sc *Scan) Run(pCh chan int, rCh chan ScanResult) {
	createWorkerPool(*sc, pCh, rCh)

}

func (sc *Scan) String() string {
	delayStr := func() string {
		if sc.delayEnabled {
			return fmt.Sprint(sc.delayTime)
		} else {
			return "Disabled"
		}
	}
	threadStr := func() string {
		if sc.ThreadCount != 100 {
			return fmt.Sprint(sc.ThreadCount)
		} else {
			return "Default"
		}
	}
	return fmt.Sprintf("Scan Type: %s\nAddress: %s\tPorts: %s\nDelay: %s\t\tThreads: %s\n", strings.ToUpper(sc.ScanType), sc.Address, sc.Port.info(), delayStr(), threadStr())
}

func BuildScan(scanType string, addr string, delay time.Duration, portStr string, threadCount int) (bS Scan, e error) {
	dEnabled := (delay != 0)

	if p, e := parsePorts(portStr); e != nil {
		return bS, e
	} else {
		if threadCount > p.Total {
			fmt.Fprintf(os.Stdout, "NOTICE: Number of threads  > number of ports\nThreads limited to port total: %d\n", p.Total)
			threadCount = p.Total
		}

		bS = Scan{
			scanType,
			addr,
			p,
			dEnabled,
			delay,
			threadCount,
		}
	}
	return bS, e
}

func (p *PortData) info() (s string) {
	switch p.Format {
	case 3:
		s = fmt.Sprintf("%d-%d:", p.Min, p.Max)
		for i := 0; i < len(p.List); i++ {
			if i != len(p.List)-1 {
				s += fmt.Sprintf("%d,", p.List[i])
			} else {
				s += fmt.Sprintf("%d", p.List[i])
			}
		}
	case 2:
		s = fmt.Sprintf("%d-%d", p.Min, p.Max)
	case 1:
		for i := 0; i < len(p.List); i++ {
			if i != len(p.List)-1 {
				s += fmt.Sprintf("%d,", p.List[i])
			} else {
				s += fmt.Sprintf("%d", p.List[i])
			}
		}
	}
	return s
}

func (sR *ScanResult) String() string {
	return fmt.Sprintf("%s %d %s", sR.Protocol, sR.Port, sR.State)
}

//Implement sort.Interface to enable sorting of ScanResults
func (sRS ScanResSort) Len() int {
	return len(sRS)
}
func (sRS ScanResSort) Less(i, j int) bool {
	return sRS[i].Port < sRS[j].Port
}
func (sRS ScanResSort) Swap(i, j int) {
	sRS[i], sRS[j] = sRS[j], sRS[i]
}

// parsePorts(portStr) (portData, error) -
func parsePorts(portStr string) (PortData, error) {
	const (
		RANGE_EXP = `\d+-\d+`     //regex for port range
		LIST_EXP  = `(\d+,|\d+)+` //regex for port list
	)
	var ports PortData

	portStr = strings.Trim(portStr, " ")

	//Helper for range format
	rangeParse := func(s string) {
		tok := strings.Split(s, "-")
		ports.Min, _ = strconv.Atoi(tok[0])
		ports.Max, _ = strconv.Atoi(tok[1])
	}
	//Helper for list format
	listParse := func(s string) {
		tok := strings.Split(s, ",")
		for _, v := range tok {
			p, _ := strconv.Atoi(v)
			ports.List = append(ports.List, p)
		}
	}

	//Parse input port format, range, literals, or combo
	//Set total number of ports (ports.total)
	if b, e := regexp.MatchString(RANGE_EXP+`::`+LIST_EXP, portStr); b && e == nil {
		s := strings.Split(portStr, "::")
		rangeParse(s[0])
		listParse(s[1])
		ports.Total = ports.Max - ports.Min + len(ports.List) + 1
		ports.Format = 3
	} else if b, e := regexp.MatchString(RANGE_EXP, portStr); b && e == nil {
		rangeParse(portStr)
		ports.Total = ports.Max - ports.Min + 1
		ports.Format = 2
	} else if b, e := regexp.MatchString(LIST_EXP, portStr); b && e == nil {
		listParse(portStr)
		ports.Total = len(ports.List)
		ports.Format = 1
	} else {
		return ports, errors.New("could not parse provided port range/list - " + portStr)
	}
	return ports, nil
}
