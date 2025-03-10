//go:build !bpfman

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 app bpfapp.c

import (
	"errors"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func load() (map[string]*ebpf.Map, []closer, error) {
	var closers []closer

	// Remove resource limits for kernels <5.11.
	// ---------------------------------------------------------
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Println("error removing memlock")
		return nil, nil, err
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	// ---------------------------------------------------------
	var objs appObjects
	if err := loadAppObjects(&objs, nil); err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			log.Printf("%+v\n", verr)
		}
		log.Println("error loading eBPF objects")
		return nil, nil, err
	}
	closers = append(closers, &objs)

	// Link probes
	// ---------------------------------------------------------
	ex, err := link.OpenExecutable(EXECUTABLE_PATH)
	if err != nil {
		log.Println("error opening executable")
		earlyClose(closers)
		return nil, nil, err
	}

	entryRead, err := ex.Uprobe("SSL_read", objs.EntrySslRead, nil)
	if err != nil {
		log.Println("error attaching uprobe")
		earlyClose(closers)
		return nil, nil, err
	}
	closers = append(closers, entryRead)

	retRead, err := ex.Uretprobe("SSL_read", objs.RetSslRead, nil)
	if err != nil {
		log.Println("error attaching uretprobe")
		earlyClose(closers)
		return nil, nil, err
	}
	closers = append(closers, retRead)

	// Define maps
	// ---------------------------------------------------------
	maps := make(map[string]*ebpf.Map)
	maps["rcount"] = objs.Rcount

	return maps, closers, nil

}
