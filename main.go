/*
	Revise parsing of ports ranges, fails to properly parse range and literals (ex. 1-1024 1025,1026)
		example usage that fails: go run main.go -s -p 1-1024 1025,1026 127.0.0.1
		rethink either acceptable input or parsing
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
	total  int
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
	flag.StringVar(&portStr, "p", PORTS_DEFAULT, "`port range` in either 1-1024, 1,2,3,4, or 1-1024 1,2,3,4 format")
	flag.IntVar(&options.threadCount, "t", THREAD_DEFAULT, "Number of threads(i.e. goroutines) to use")
	flag.DurationVar(&options.waitTime, "wait", WAIT_DEFAULT, "Set wait time between scan attempts, e.g. 500ms or 2s")
	flag.Parse()

	// Check if IP or URL has been passed, else terminate
	if addr := flag.Arg(0); addr != "" {
		options.address = addr
	} else {
		fmt.Fprintf(os.Stderr, "Usage: go-brrr-scanner [-s] IP/URL\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	//Check for proper port
	var e error
	options.ports, e = parsePorts(portStr)
	if e != nil {
		fmt.Fprintf(os.Stderr, "Oh no, something went wrong: %s", e.Error())
		flag.PrintDefaults()
		os.Exit(1)
	}
}

// CHANGE THIS
func main() {

	// this channel will receive ports to be scanned
	portsChan := make(chan int, options.threadCount)
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

	for i := 0; i < options.ports.total; i++ {
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

func parsePorts(portStr string) (portData, error) {
	//Initialize
	var ports portData
	ports.absMax = PORT_ABS_MAX

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
	if b, e := regexp.MatchString(RANGE_EXP+` `+LIST_EXP, portStr); b && e == nil {
		p := strings.Split(" ", portStr)
		rangeParse(p[0])
		listParse(p[1])
		ports.total = ports.max - ports.min + len(ports.list)
	} else if b, e := regexp.MatchString(RANGE_EXP, portStr); b && e == nil {
		rangeParse(portStr)
		ports.total = ports.max - ports.min
	} else if b, e := regexp.MatchString(LIST_EXP, portStr); b && e == nil {
		listParse(portStr)
		ports.total = len(ports.list)
	} else {
		return ports, errors.New("could not parse provided port range/list - " + portStr)
	}
	return ports, nil
}
