package main

import (
	"log"
	"os"
	"os/signal"
	"time"
)

const EXECUTABLE_PATH = "/lib/x86_64-linux-gnu/libssl.so.3"

var (
	key   uint32
	value uint32
)

type closer interface {
	Close() error
}

func earlyClose(closers []closer) {
	for _, c := range closers {
		if err := c.Close(); err != nil {
			log.Println("error attempting to call Close:", err)
		}
	}
}

func main() {
	log.Println("howdy!")
	defer log.Println("bye!")

	maps, closers, err := load()
	if err != nil {
		log.Fatal(err)
	}
	for _, c := range closers {
		defer c.Close()
	}

	seen := make(map[string]map[uint32]uint32, len(maps))

	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	log.Println("Waiting for SSL_read calls...")
	for {
		select {
		case <-tick:

			for name, m := range maps {
				if seen[name] == nil {
					seen[name] = make(map[uint32]uint32)
				}

				entries := m.Iterate()
				for entries.Next(&key, &value) {
					if value == seen[name][key] {
						continue
					}
					log.Printf("Map: %s, PID: %d [%x], count: %d", name, key, key, value)
					seen[name][key] = value
				}

				if err := entries.Err(); err != nil {
					log.Println("Iterator encountered an error:", err)
				}
			}
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}

}
