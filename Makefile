.PHONY : clean build bpfman-build injection full-injection image container shell stop bpfman-nginx-image bpfman-nginx-container nginx-container
path?=/

clean:
	rm -f app *bpfeb.go *bpfeb.o *bpfel.go *bpfel.o

build: clean
	go generate
	go build .

bpfman-build: clean
	go generate bpfman.go
	go build --tags=bpfman .

injection:
	docker exec $(container) rm $(path)app $(path)app_x86_bpfel.o; docker cp app $(container):$(path)app

full-injection:
	docker exec $(container) rm $(path)app $(path)app_x86_bpfel.o; docker cp app $(container):$(path)app && docker cp app_x86_bpfel.o $(container):$(path)app_x86_bpfel.o

stop:
	docker stop bpnx nx tapp; docker rm bpnx nx tapp; docker rmi bpfman-nginx:test app:test; docker ps

image: bpfman-build
	docker build -t app:test -f Containerfile.app .

container: stop image
	docker stop tapp; sleep 1; docker run -d --rm --name tapp --privileged -v /proc:/host/proc -v /sys/fs/bpf:/sys/fs/bpf -e RUST_LOG="Debug" -e UPROBE_HOST_PID=$(cpid) app:test
	docker exec -it tapp /app

shell:
	docker exec -it $(container) bash

bpfman-nginx-image:
	docker build -t bpfman-nginx:test -f Containerfile.nginx .

bpfman-nginx-container: stop bpfman-nginx-image
	sleep 1; docker run -d --rm --name bpnx --privileged -v /sys/fs/bpf:/sys/fs/bpf -e RUST_LOG="Debug" -p 8080:8080 bpfman-nginx:test

nginx-container: stop bpfman-nginx-image
	sleep 1; docker run -d --rm --name nx --privileged -p 8080:8080 bpfman-nginx:test