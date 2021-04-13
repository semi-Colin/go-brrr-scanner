/*
	REVISE: sending ports to be scanned repeats logic used in parsePorts, consider restructuring
	PARTIAL FIX: port parsing
	ISSUE: goroutine panic
	Enable/disable scanning based on flag types

	Review var,const, and init
	Rewrite if possible to avoid global vars

	COMMENT YOUR CODE YOU BARBARIAN - me to me
*/

package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	CAN_SCAN       = false         //default scan settings
	PORTS_DEFAULT  = "1-1024"      //default port range
	WAIT_DEFAULT   = 1000000000    //duration in ms
	THREAD_DEFAULT = 100           //default goroutine count
	RANGE_EXP      = `\d+-\d+`     //regex for port range
	LIST_EXP       = `(\d+,|\d+)+` //regex for port list
)

type portData struct {
	format int   //indicator for combo(3), range (2), or list (1)
	list   []int //holds ports provided as list
	min    int   //min range
	max    int   //max range
	total  int   //total ports
}

type operatingOptions struct {
	threadCount int
	address     string
	waitTime    time.Duration
	ports       portData
}

var (
	synFlag, tcpFlag, ackFlag, udpFlag, verbFlag bool
	portStr                                      string
	options                                      operatingOptions
)

// init() - parse flags, initialize some vars, sanity check
func init() {
	flag.BoolVar(&synFlag, "s", CAN_SCAN, "SYN stealth scan")
	flag.BoolVar(&tcpFlag, "sT", CAN_SCAN, "TCP connect scan")
	flag.BoolVar(&ackFlag, "sA", CAN_SCAN, "ACK scan")
	flag.BoolVar(&udpFlag, "sU", CAN_SCAN, "UDP scan")
	flag.StringVar(&portStr, "p", PORTS_DEFAULT, "`port range` in either 1-1024, 1,2,3,4, or 1-1024::1,2,3,4 format")
	flag.IntVar(&options.threadCount, "t", THREAD_DEFAULT, "Number of threads(i.e. goroutines) to use")
	flag.DurationVar(&options.waitTime, "wait", WAIT_DEFAULT, "Set wait time between scan attempts, e.g. 500ms or 2s")
	flag.BoolVar(&verbFlag, "v", false, "Verbosity level 1 - shows closed ports and open ports")
	flag.Parse()

	// Check if IP or URL has been passed, else terminate
	if addr := flag.Arg(0); addr != "" {
		options.address = addr
	} else {
		fmt.Fprintf(os.Stderr, "Usage: go-brrr-scanner [-s] IP/URL\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	//Check for proper port and set threadCount
	var e error
	options.ports, e = parsePorts(portStr)
	if e != nil {
		fmt.Fprintf(os.Stderr, "Oh no, something went wrong: %s", e.Error())
		flag.PrintDefaults()
		os.Exit(1)
	}
	//prevent more threads than ports
	if options.threadCount > options.ports.total {
		options.threadCount = options.ports.total
	}
}

// main() -
func main() {
	// create a slice to store the results so that they can be sorted later.
	var openports []int
	// this channel will receive ports to be scanned
	portsChan := make(chan int, options.threadCount)
	// this channel will receive results of scanning
	resultsChan := make(chan int)

	// create a pool of workers and send ports for scanning
	createWorkerPool(options, portsChan, resultsChan)
	go fillPortsChan(options, portsChan)

	// empty channel to openports
	for i := 0; i < options.ports.total; i++ {
		port := <-resultsChan
		if port != 0 {
			openports = append(openports, port)
		}
	}

	// After all the work has been completed, close the channels
	defer close(portsChan)
	defer close(resultsChan)

	// sort open port numbers
	sort.Ints(openports)
	for _, port := range openports {
		fmt.Printf("%d open\n", port)
	}
}

// worker(addr, pCh, rCh) - worker in goroutine dialing ports and logging connections
func worker(addr string, pCh, rCh chan int) {
	for p := range pCh {
		fullAddr := fmt.Sprintf("%s:%d", addr, p)
		conn, err := net.Dial("tcp", fullAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not connect: %s\n", err.Error())
			rCh <- 0
			continue
		}
		conn.Close()
		rCh <- p
	}
}

// createWorkerPool(o, pCh, rCh) - run each worker as goroutine x threadCount
func createWorkerPool(o operatingOptions, pCh chan int, rCh chan int) {
	for i := 0; i < o.threadCount; i++ {
		go worker(o.address, pCh, rCh)
	}
}

//fillPortsChan(o, pCh) - depending on format, send ports to be scanned
func fillPortsChan(o operatingOptions, pCh chan int) {
	//REVISE: repeated logic from parsePorts, determining range vs list vs combo
	switch o.ports.format {
	case 3:
		for i := options.ports.min; i <= options.ports.max; i++ {
			pCh <- i
		}
		for _, v := range options.ports.list {
			pCh <- v
		}
	case 2:
		for i := options.ports.min; i <= options.ports.max; i++ {
			pCh <- i
		}
	case 1:
		for _, v := range options.ports.list {
			pCh <- v
		}
	}
}

// parsePorts(portStr) (portData, error) -
func parsePorts(portStr string) (portData, error) {
	var ports portData

	//Helper for range format
	rangeParse := func(s string) {
		tok := strings.Split(s, "-")
		ports.min, _ = strconv.Atoi(tok[0])
		ports.max, _ = strconv.Atoi(tok[1])
	}
	//Helper for list format
	listParse := func(s string) {
		tok := strings.Split(s, ",")
		for _, v := range tok {
			p, _ := strconv.Atoi(v)
			ports.list = append(ports.list, p)
		}
	}

	//Parse input port format, range, literals, or combo
	//Set total number of ports (ports.total)
	if b, e := regexp.MatchString(RANGE_EXP+`::`+LIST_EXP, portStr); b && e == nil {
		p := strings.Split("::", portStr)
		rangeParse(p[0])
		listParse(p[1])
		ports.total = ports.max - ports.min + len(ports.list)
		ports.format = 3
	} else if b, e := regexp.MatchString(RANGE_EXP, portStr); b && e == nil {
		rangeParse(portStr)
		ports.total = ports.max - ports.min
		ports.format = 2
	} else if b, e := regexp.MatchString(LIST_EXP, portStr); b && e == nil {
		listParse(portStr)
		ports.total = len(ports.list)
		ports.format = 1
	} else {
		return ports, errors.New("could not parse provided port range/list - " + portStr)
	}
	return ports, nil
}
