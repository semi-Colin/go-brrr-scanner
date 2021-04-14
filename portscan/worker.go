// Eventually for moving out concurrency and parallelism from main

package portscan

import (
	"fmt"
	"net"
)

// worker(addr, pCh, rCh) - worker in goroutine dialing ports and logging connections
func worker(addr string, protocol string, pCh chan int, rCh chan ScanResult) {
	for p := range pCh {
		fullAddr := fmt.Sprintf("%s:%d", addr, p)
		conn, err := net.Dial(protocol, fullAddr)
		if err != nil {
			rCh <- ScanResult{
				p,
				"closed",
				protocol,
				"NA",
			}
			continue
		}
		conn.Close()
		rCh <- ScanResult{
			p,
			"open",
			protocol,
			"NA",
		}
	}
}

// createWorkerPool(o, pCh, rCh) - run each worker as goroutine x threadCount
func createWorkerPool(sc Scan, pCh chan int, rCh chan ScanResult) {
	for i := 0; i < sc.ThreadCount; i++ {
		go worker(sc.Address, sc.ScanType, pCh, rCh)

	}
}
