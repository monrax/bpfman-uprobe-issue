FROM quay.io/bpfman/bpfman:v0.5.6

RUN apt update -y && apt install -y curl
COPY app app_x86_bpfel.o /
