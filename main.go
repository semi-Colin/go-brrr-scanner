/*
	Possible revise line 19 to change to nested struct
		Want to accept ports as range 1-1024 and also as 1,2,3,4 or just 80
	Review var,const, and init
	Rethink control flow and options

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
	CAN_SCAN       = false
	PORTS_DEFAULT  = "1-1024"
	WAIT_DEFAULT   = 1000000000 //duration in ms
	PORT_ABS_MAX   = 65353
	THREAD_DEFAULT = 100
	RANGE_EXP      = `\d+-\d+`
	LIST_EXP       = `(\d+,|\d+)+`
)

type portData struct {
	list   []int
	min    int
	max    int
	absMax int
}

type operatingOptions struct {
	threadCount int
	address     string
	waitTime    time.Duration
	ports       portData
}

var (
	synFlag, tcpFlag, ackFlag, udpFlag bool
	portStr                            string
	options                            operatingOptions
)

func init() {
	flag.BoolVar(&synFlag, "s", CAN_SCAN, "SYN stealth scan")
	flag.BoolVar(&tcpFlag, "sT", CAN_SCAN, "TCP connect scan")
	flag.BoolVar(&ackFlag, "sA", CAN_SCAN, "ACK scan")
	flag.BoolVar(&udpFlag, "sU", CAN_SCAN, "UDP scan")
	flag.StringVar(&portStr, "p", PORTS_DEFAULT, "`port range` in either 1-1024 or 1,2,3,4 format")
	flag.IntVar(&options.threadCount, "t", THREAD_DEFAULT, "Number of threads(i.e. goroutines) to use")
	flag.DurationVar(&options.waitTime, "wait", WAIT_DEFAULT, "Set wait time between scan attempts, e.g. 500ms or 2s")
	flag.Parse()
	if addr := flag.Arg(0); addr != "" {
		options.address = addr
	} else {
		fmt.Fprintf(os.Stderr, "Usage: go-brrr-scanner [-s] IP/URL\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	var e error
	options.ports, e = parsePorts(portStr)
	if e != nil {
		fmt.Fprintf(os.Stderr, "Oh no, something went wrong: %s", e.Error())
		flag.PrintDefaults()
		os.Exit(1)
	}
}

func parsePorts(portStr string) (portData, error) {
	var ports portData
	ports.absMax = PORT_ABS_MAX

	rangeParse := func(s string) {
		tok := strings.Split(s, "-")
		ports.min, _ = strconv.Atoi(tok[0])
		ports.max, _ = strconv.Atoi(tok[1])
	}
	listParse := func(s string) {
		tok := strings.Split(s, ",")
		for _, v := range tok {
			p, _ := strconv.Atoi(v)
			ports.list = append(ports.list, p)
		}
	}

	if b, e := regexp.MatchString(RANGE_EXP+` `+LIST_EXP, portStr); b && e == nil {
		p := strings.Split(" ", portStr)
		rangeParse(p[0])
		listParse(p[1])
	} else if b, e := regexp.MatchString(RANGE_EXP, portStr); b && e == nil {
		rangeParse(portStr)
	} else if b, e := regexp.MatchString(LIST_EXP, portStr); b && e == nil {
		listParse(portStr)
	} else {
		return ports, errors.New("could not parse provided port range/list - " + portStr)
	}
	return ports, nil
}

// CHANGE THIS
func worker(addr string, pCh, rCh chan int) {
	for p := range pCh {
		fullAddr := fmt.Sprintf("%s:%d", addr, p)
		conn, err := net.Dial("tcp", fullAddr)
		if err != nil {
			rCh <- 0
			continue
		}
		conn.Close()
		rCh <- p
	}
}

// CHANGE THIS
func main() {
	fmt.Printf("%d-%d\n", options.ports.min, options.ports.max)
	// this channel will receive ports to be scanned
	portsChan := make(chan int, 100)
	// this channel will receive results of scanning
	resultsChan := make(chan int)
	// create a slice to store the results so that they can be sorted later.
	var openports []int

	// create a pool of workers
	for i := 0; i < cap(portsChan); i++ {
		go worker(options.address, portsChan, resultsChan)
	}

	// send ports to be scanned
	go func() {
		for i := options.ports.min; i <= options.ports.max; i++ {
			portsChan <- i
		}
	}()

	for i := 0; i < 1024; i++ {
		port := <-resultsChan
		if port != 0 {
			openports = append(openports, port)
		}
	}

	// After all the work has been completed, close the channels
	close(portsChan)
	close(resultsChan)
	// sort open port numbers
	sort.Ints(openports)
	for _, port := range openports {
		fmt.Printf("%d open\n", port)
	}
}
