/*
	REVISE: sending ports to be scanned repeats logic used in parsePorts, consider restructuring
	Enable/disable scanning based on flag types
	COMMENT YOUR CODE YOU BARBARIAN - me to me
*/
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/semi-Colin/go-brrr-scanner/portscan"
)

const (
	CAN_SCAN       = false    //default scan settings
	PORTS_DEFAULT  = "1-1024" //default port range
	DELAY_DEFAULT  = 0        //duration in ms
	THREAD_DEFAULT = 100      //default goroutine count

)

// main() -
func main() {

	var (
		synFlag, tcpFlag, ackFlag, udpFlag, verbFlag bool
		portStr                                      string
		delay                                        time.Duration
		threadCount                                  int
	)

	//parse flags, initialize vars, sanity check
	flag.BoolVar(&synFlag, "s", CAN_SCAN, "SYN TCP Half-open scan")
	flag.BoolVar(&tcpFlag, "sT", CAN_SCAN, "TCP connect scan")
	flag.BoolVar(&ackFlag, "sA", CAN_SCAN, "ACK scan")
	flag.BoolVar(&udpFlag, "sU", CAN_SCAN, "UDP scan")
	flag.StringVar(&portStr, "p", PORTS_DEFAULT, "`port range` in either 1-1024, 1,2,3,4, or 1-1024::1,2,3,4 format")
	flag.IntVar(&threadCount, "t", THREAD_DEFAULT, "Number of threads(i.e. goroutines) to use")
	flag.DurationVar(&delay, "delay", DELAY_DEFAULT, "Set wait time between scan attempts, e.g. 500ms or 2s")
	flag.BoolVar(&verbFlag, "v", false, "Verbosity - shows scan statistics + closed & open ports")
	flag.Parse()

	var sType string
	switch {
	case synFlag:
		sType = "syn"
	case tcpFlag:
		sType = "tcp"
	case ackFlag:
		sType = "ack"
	case udpFlag:
		sType = "udp"
	}
	var scan portscan.Scan
	var err error
	addr := flag.Arg(0)
	if scan, err = portscan.BuildScan(sType, addr, delay, portStr, threadCount); err != nil {
		fmt.Fprintf(os.Stderr, "Oh no, something went wrong: %s", err.Error())
		flag.PrintDefaults()
	}

	// create a slice to store the results so that they can be sorted later.
	//var openports []int
	var allports portscan.ScanResSort
	// this channel will receive ports to be scanned
	portsChan := make(chan int, scan.ThreadCount)
	// this channel will receive results of scanning
	resultsChan := make(chan portscan.ScanResult)

	if verbFlag {
		fmt.Println(scan.String())
	}
	scan.Run(portsChan, resultsChan)
	go fillPortsChan(scan, portsChan)

	// empty channel to openports
	for i := 0; i < scan.Port.Total; i++ {
		res := <-resultsChan
		allports = append(allports, res)
		/*if res.State != "closed" {
			openports = append(openports, res.Port)
		}*/
	}
	// After all the work has been completed, close the channels
	defer close(portsChan)
	defer close(resultsChan)

	//Printts out all ports scanned and state
	sort.Sort(allports)
	for _, p := range allports {
		fmt.Println(p.String())
	}

	// sort open port numbers
	/*sort.Ints(openports)
	for _, port := range openports {
		fmt.Printf("%d open\n", port)
	}*/

}

//fillPortsChan(o, pCh) - depending on format, send ports to be scanned
func fillPortsChan(sc portscan.Scan, pCh chan int) {
	//REVISE: repeated logic from parsePorts, determining range vs list vs combo

	switch sc.Port.Format {
	case 3:
		for i := sc.Port.Min; i <= sc.Port.Max; i++ {
			pCh <- i
		}
		for _, v := range sc.Port.List {
			pCh <- v
		}
	case 2:
		for i := sc.Port.Min; i <= sc.Port.Max; i++ {
			pCh <- i
		}
	case 1:
		for _, v := range sc.Port.List {
			pCh <- v
		}
	}
}
