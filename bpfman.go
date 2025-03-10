//go:build bpfman

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cflags '-DPIN_BY_NAME' app bpfapp.c

import (
	"context"
	"errors"
	"log"
	"os"
	"strconv"

	bpfmanHelpers "github.com/bpfman/bpfman-operator/pkg/helpers"
	gobpfman "github.com/bpfman/bpfman/clients/gobpfman/v1"
	configMgmt "github.com/bpfman/bpfman/examples/pkg/config-mgmt"
	"github.com/cilium/ebpf"
	"google.golang.org/grpc"
)

const (
	DefaultByteCodeFile = "app_x86_bpfel.o"
	BpfProgramMapIndex1 = "rcount"
	MapsMountPoint      = "/run/probes/maps"
)

type program struct {
	id     uint32
	ctx    context.Context
	conn   *grpc.ClientConn
	client *gobpfman.BpfmanClient
}

func (prog *program) Close() error {
	log.Printf("unloading program: %d\n", prog.id)
	client := *prog.client
	_, err := client.Unload(prog.ctx, &gobpfman.UnloadRequest{Id: prog.id})
	prog.conn.Close()
	if err != nil {
		log.Print(err)
	}
	return err
}

func load() (map[string]*ebpf.Map, []closer, error) {
	var closers []closer
	var programs [2]*program
	var loadRequests [2]*gobpfman.LoadRequest

	var targetSymbol string = "SSL_read"
	var cpidp *int32

	maps := make(map[string]*ebpf.Map)

	opts := &ebpf.LoadPinOptions{
		ReadOnly:  false,
		WriteOnly: false,
		Flags:     0,
	}

	mapNames := []string{
		BpfProgramMapIndex1,
	}

	if cPid, ok := os.LookupEnv("UPROBE_HOST_PID"); ok {
		if pid, err := strconv.Atoi(cPid); err == nil {
			cpid := int32(pid)
			cpidp = &cpid
		} else {
			log.Println("couldn't parse host pid")
			return nil, nil, err
		}
	} else {
		log.Println("UPROBE_HOST_PID is not set. Will not attempt to attach probes to another container.")
		cpidp = nil
	}

	// pull the BPFMAN config management data to determine if we're running on a system with BPFMAN available.
	paramData, err := configMgmt.ParseParamData(configMgmt.ProgTypeApplication, DefaultByteCodeFile)
	if err != nil {
		log.Println("error processing parameters")
		return nil, nil, err
	}

	// connect to the BPFMAN server
	ctx := context.Background()
	conn, err := configMgmt.CreateConnection(ctx)
	if err != nil {
		log.Println("failed to create client connection")
		return nil, nil, err
	}
	closers = append(closers, conn)

	client := gobpfman.NewBpfmanClient(conn)

	// define requests to load bpf programs
	loadRequests[0] = &gobpfman.LoadRequest{
		Bytecode:    paramData.BytecodeSource,
		Name:        "entry_ssl_read",
		ProgramType: *bpfmanHelpers.Kprobe.Uint32(),
		Attach: &gobpfman.AttachInfo{
			Info: &gobpfman.AttachInfo_UprobeAttachInfo{
				UprobeAttachInfo: &gobpfman.UprobeAttachInfo{
					FnName:       &targetSymbol,
					Target:       EXECUTABLE_PATH,
					ContainerPid: cpidp,
					Retprobe:     false,
				},
			},
		},
	}

	loadRequests[1] = &gobpfman.LoadRequest{
		Bytecode:    paramData.BytecodeSource,
		Name:        "ret_ssl_read",
		ProgramType: *bpfmanHelpers.Kprobe.Uint32(),
		Attach: &gobpfman.AttachInfo{
			Info: &gobpfman.AttachInfo_UprobeAttachInfo{
				UprobeAttachInfo: &gobpfman.UprobeAttachInfo{
					FnName:       &targetSymbol,
					Target:       EXECUTABLE_PATH,
					ContainerPid: cpidp,
					Retprobe:     true,
				},
			},
		},
	}

	// load programs
	for i, req := range loadRequests {
		if i != 0 {
			req.MapOwnerId = &programs[0].id
		}

		programs[i] = &program{
			ctx:    ctx,
			conn:   conn,
			client: &client,
		}

		closers = append(closers, programs[i])

		res, err := client.Load(ctx, req)
		if err != nil {
			log.Println("Error loading program", req.Name)
			earlyClose(closers)
			return nil, nil, err
		}

		log.Printf("program %s loaded!", res.GetInfo().Name)

		kernelInfo := res.GetKernelInfo()
		if kernelInfo != nil {
			(*programs[i]).id = uint32(kernelInfo.GetId())
		} else {
			earlyClose(closers)
			return nil, nil, errors.New("kernelInfo not returned in LoadResponse")
		}

		log.Println("program id:", programs[i].id)

		for j, name := range mapNames {
			path, err := configMgmt.CalcMapPinPath(res.GetInfo(), name)
			if err != nil {
				earlyClose(closers)
				return nil, nil, err
			}
			if i == 0 {
				m, err := ebpf.LoadPinnedMap(path, opts)
				if err != nil {
					log.Println("Failed to load pinned Map:", path)
					earlyClose(closers)
					return nil, nil, err
				}
				maps[name] = m
			}
			if j == 0 {
				log.Println("maps:")
			}
			log.Printf(" - %s: %s", name, path)
		}
	}

	return maps, closers, nil
}
