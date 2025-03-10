# Issue: is the execution of uprobes and uretprobes reversed when using bpfman-ns?

When running a simple eBPF application comprised of one `uprobe` and one` uretprobe` for the same symbol, the expected result is for the `uprobe` program to be called before the `uretprobe` one. However, it appears that when attaching these probes to the same location in a different mount namespace using `bpfman-ns`, and running the same application, the effect is the opposite.

Found this issue while attempting to attach probes to OpenSSL function calls from one container to another using bpfman.

## The app

`bpfapp.c` is a simple eBPF application that counts each call made from a different process to the OpenSSL 
function `SSL_read`. The count is then stored in a map named `rcount`, which is periodically accessed by a
Go application `app.go` each second, printing out any new available key-value pairs.

The app consists of two programs: `entry_ssl_read` (**uprobe**) and `ret_ssl_read` (**uretprobe**).

Each time `entry_ssl_read` executes, it updates the count using the current PID as key.

Each time `ret_ssl_read` executes, it updates the count using a hard-coded u32 (0xBEBECAFE) as key.

In addition, each time any of these programs executes, a new message is logged to `/sys/kernel/tracing/trace`
using `bpf_trace_printk` with the following format:

```
[<program type>/SSL_read] got here!
```

with `<program type>` being either `uprobe` or `uretprobe` accordingly.


## The files

- `bpfapp.c`: eBPF application

- `app.go`, `cilium.go`, `bpfman.go`, `go.mod`, `go.sum`: userspace Go application

  - `cilium.go`: defines `load()` to load ebpf programs using Cilium's [ebpf-go](https://ebpf-go.dev/)

  - `bpfman.go`: defines `load()` to load ebpf programs using Bpfman.io's [bpfman](https://bpfman.io/v0.5.6/)

- `Containerfile.app`: defines a container image built from `quay.io/bpfman/bpfman:v0.5.6`, that includes both the final `app` executable and the clang-built `app_x86_bpfel.o` object file.

- `Containerfile.nginx`: defines a container image built from `quay.io/bpfman/bpfman:v0.5.6`, that includes a TLS-enabled nginx application that exposes the `/` and `/json` endpoints through port `8080`.

## Using Cilium's ebpf-go

As control, for the first two cases we will use ebpf-go functions to load our eBPF programs into the kernel directly.
The outcome should be the same in both: the `uprobe` program executes first, and then the `uretprobe` program.

### Case 1: Running the app directly from host machine
- Build the application
- The resulting binary is executed from host shell

```sh
make build
sudo ./app
```

- In another shell, make an HTTPS request using curl

```sh
curl https://httpbin.org/get
```

- The first shell should look similar to this:
```
2025/03/10 12:15:02 howdy!
2025/03/10 12:15:02 Waiting for SSL_read calls...
2025/03/10 12:15:05 Map: rcount, PID: 6679 [1a17], count: 2
2025/03/10 12:15:05 Map: rcount, PID: 3200174846 [bebecafe], count: 2
```

- Finally, we can stop our program with `ctrl + c` and read our `bpf_trace_printk` messages

```
sudo cat /sys/kernel/tracing/trace
```

- The result should look like this:
```
#           TASK-PID     CPU#  |||||  TIMESTAMP  FUNCTION
#              | |         |   |||||     |         |
            curl-6679    [007] ...11   402.234559: bpf_trace_printk: [uprobe/SSL_read] got here!
            curl-6679    [007] ...11   402.234681: bpf_trace_printk: [uretprobe/SSL_read] got here!
            curl-6679    [007] ...11   402.234696: bpf_trace_printk: [uprobe/SSL_read] got here!
            curl-6679    [007] ...11   402.234705: bpf_trace_printk: [uretprobe/SSL_read] got here!
```

With the outcome being first `uprobe`, then `uretprobe` as expected.

### Case 2: Running the app from target container
- Build the target nginx container and verify it is running

```sh
make nginx-container
docker ps | grep nx
```

- Build the application
- The resulting binary is copied into the running container

```sh
make build
make injection container=nx path=/
```

- The bpf application is executed from the container shell

```sh
make shell container=nx
./app
```

- In another host shell session, make an HTTPS request to the nginx service in the running container using curl. You might need to add a new entry to your `/etc/hosts` with the name expected by the TLS certificate: `neptune`

```sh
sudo echo 127.0.0.1 neptune >> /etc/hosts

curl -k https://neptune:8080/json
```

- The container shell should look similar to this:
```
2025/03/10 12:14:56 howdy!
2025/03/10 12:14:56 Waiting for SSL_read calls...
2025/03/10 12:15:05 Map: rcount, PID: 3200174846 [bebecafe], count: 3
2025/03/10 12:15:05 Map: rcount, PID: 22157 [568d], count: 3
```

- Finally, we can stop our program with `ctrl + c`, `exit` the container shell, and read our `bpf_trace_printk` messages

```
sudo cat /sys/kernel/tracing/trace
```

- The result should look like this:
```
#           TASK-PID     CPU#  |||||  TIMESTAMP  FUNCTION
#              | |         |   |||||     |         |
           nginx-22157   [003] ...11  4001.057085: bpf_trace_printk: [uprobe/SSL_read] got here!
           nginx-22157   [003] ...11  4001.057140: bpf_trace_printk: [uretprobe/SSL_read] got here!
           nginx-22157   [003] ...11  4001.057144: bpf_trace_printk: [uprobe/SSL_read] got here!
           nginx-22157   [003] ...11  4001.057153: bpf_trace_printk: [uretprobe/SSL_read] got here!
           nginx-22157   [003] ...11  4001.057601: bpf_trace_printk: [uprobe/SSL_read] got here!
           nginx-22157   [003] ...11  4001.057620: bpf_trace_printk: [uretprobe/SSL_read] got here!
```

With the outcome being first `uprobe`, then `uretprobe` as expected as well.


## Using Bpfman

In the following cases 3 and 4, the `--tags=bpfman` Go build tag is set in order to build the bpf application. This has two effects:

1. Uses `bpfman.go`'s `load()` function instead of `cilium.go`'s. This makes a `gobpfman.LoadRequest` for each eBPF program, which is used to request through the `bpfman` API (using `bpfman-rpc`), that `bpfman` load all the programs acoordingly.

2. Adds `__uint(pinning, LIBBPF_PIN_BY_NAME);` to the `rcount` map definition in `bpfapp.c`.

### Case 3: Running the app from target container, with bpfman-rpc server

- Build the target bpfman-nginx container and verify it is running

```sh
make bpfman-nginx-container
docker ps | grep bpnx
```

- Build the application
- The resulting binary is copied into the running container

```sh
make bpfman-build
make full-injection container=bpnx path=/
```

- The bpf application is executed from the container shell

```sh
make shell container=bpnx
./app
```

- In another host shell session, make an HTTPS request to the nginx service in the running container using curl. You might need to add a new entry to your `/etc/hosts` with the name expected by the TLS certificate: `neptune`

```sh
sudo echo 127.0.0.1 neptune >> /etc/hosts

curl -k https://neptune:8080/json
```

- The container shell should look similar to this:
```
2025/03/10 12:25:51 howdy!
2025/03/10 12:25:51 UPROBE_HOST_PID is not set. Will not attempt to attach probes to another container.
2025/03/10 12:25:51 Using Input: Interface=eno3 Priority=50 Source=/app_x86_bpfel.o
2025/03/10 12:25:54 program entry_ssl_read loaded!
2025/03/10 12:25:54 program id: 158
2025/03/10 12:25:54 maps:
2025/03/10 12:25:54  - rcount: /run/bpfman/fs/maps/158/rcount
2025/03/10 12:25:56 program ret_ssl_read loaded!
2025/03/10 12:25:56 program id: 159
2025/03/10 12:25:56 maps:
2025/03/10 12:25:56  - rcount: /run/bpfman/fs/maps/158/rcount
2025/03/10 12:25:56 Waiting for SSL_read calls...
2025/03/10 12:26:13 Map: rcount, PID: 3200174846 [bebecafe], count: 3
2025/03/10 12:26:13 Map: rcount, PID: 23770 [5cda], count: 3
```

- Finally, we can stop our program with `ctrl + c`, `exit` the container shell, and read our `bpf_trace_printk` messages

```
sudo cat /sys/kernel/tracing/trace
```

- The result should look like this:
```
#           TASK-PID     CPU#  |||||  TIMESTAMP  FUNCTION
#              | |         |   |||||     |         |
           nginx-23770   [003] ...11  4669.085686: bpf_trace_printk: [uprobe/SSL_read] got here!
           nginx-23770   [003] ...11  4669.085723: bpf_trace_printk: [uretprobe/SSL_read] got here!
           nginx-23770   [003] ...11  4669.085726: bpf_trace_printk: [uprobe/SSL_read] got here!
           nginx-23770   [003] ...11  4669.085732: bpf_trace_printk: [uretprobe/SSL_read] got here!
           nginx-23770   [000] ...11  4669.086075: bpf_trace_printk: [uprobe/SSL_read] got here!
           nginx-23770   [000] ...11  4669.086098: bpf_trace_printk: [uretprobe/SSL_read] got here!
```

With the outcome being first `uprobe`, then `uretprobe` as expected.


### Case 4: Running the app from another container

- Build the target nginx container and verify it is running

```sh
make nginx-container
docker ps | grep nx
```

- Manually copy the target container PID as seen from the host

```sh
sudo lsns -t pid
```


- Build and run the app container from `Container.app`, passing the container pid from the previous step as a make arg
```sh
make container cpid=6575
```

- In another host shell session, make an HTTPS request to the nginx service in the running container using curl. You might need to add a new entry to your `/etc/hosts` with the name expected by the TLS certificate: `neptune`

```sh
sudo echo 127.0.0.1 neptune >> /etc/hosts

curl -k https://neptune:8080/json
```

- The container shell should look similar to this:
```
2025/03/10 13:18:30 howdy!
2025/03/10 13:18:30 Using Input: Interface=eno3 Priority=50 Source=/app_x86_bpfel.o
2025/03/10 13:18:32 program entry_ssl_read loaded!
2025/03/10 13:18:32 program id: 76
2025/03/10 13:18:32 maps:
2025/03/10 13:18:32  - rcount: /run/bpfman/fs/maps/76/rcount
2025/03/10 13:18:34 program ret_ssl_read loaded!
2025/03/10 13:18:34 program id: 84
2025/03/10 13:18:34 maps:
2025/03/10 13:18:34  - rcount: /run/bpfman/fs/maps/76/rcount
2025/03/10 13:18:34 Waiting for SSL_read calls...
2025/03/10 13:18:38 Map: rcount, PID: 6600 [19c8], count: 3
2025/03/10 13:18:38 Map: rcount, PID: 3200174846 [bebecafe], count: 3
```

- Finally, we can stop our program with `ctrl + c`, `exit` the container shell, and read our `bpf_trace_printk` messages

```
sudo cat /sys/kernel/tracing/trace
```

- The result looks like this:
```
#           TASK-PID     CPU#  |||||  TIMESTAMP  FUNCTION
#              | |         |   |||||     |         |
           nginx-6600    [006] ...11   172.719103: bpf_trace_printk: [uretprobe/SSL_read] got here!
           nginx-6600    [006] ...11   172.719107: bpf_trace_printk: [uprobe/SSL_read] got here!
           nginx-6600    [006] ...11   172.719129: bpf_trace_printk: [uretprobe/SSL_read] got here!
           nginx-6600    [006] ...11   172.719130: bpf_trace_printk: [uprobe/SSL_read] got here!
           nginx-6600    [006] ...11   172.719575: bpf_trace_printk: [uretprobe/SSL_read] got here!
           nginx-6600    [006] ...11   172.719577: bpf_trace_printk: [uprobe/SSL_read] got here!
```

With the outcome being first `uretprobe`, then `uprobe` which is **NOT** the expected outcome.


## Makefile ref

- `clean`: remove all binary, intermediate, and object files previously generated
- `build`: generate intermediate and object files, and compile using ciliums's ebpf-go
- `bpfman-build`: generate object files, and compile using bpfman
- `injection`: copy `app` binary to container at specified location
- `full-injection`: copy `app` binary and `app_x86_bpel.o` object file to container at specified location
- `image`: build container image from `Container.app`
- `container`: run app container using image built with `make image`
- `shell`: exec into specified container using bash
- `stop`: stop and remove all containers mentioned here, as well as their images
- `bpfman-nginx-image`: build container from `Container.nginx`
- `bpfman-nginx-container`: run app container using image built with `make build-nginx-image`, and mounts bpffs as a volume
- `nginx-container`: run app container using image built with `make build-nginx-image`
