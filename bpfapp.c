//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#ifndef PIN_BY_NAME
    #define PIN_BY_NAME 0 
#endif

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 10);
    #if PIN_BY_NAME
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    #endif
} rcount SEC(".maps");


static int print_got_here(char* caller) {
    const static char m[] = "[%s] got here!";
    bpf_trace_printk(m, sizeof(m), caller);

    return 0;
}

static long count(__u32 *key, int isretprobe) {
    __u32* count = bpf_map_lookup_elem(&rcount, key);
    if (count == NULL) {
        if (isretprobe == 0) {
            __u32 one = 1;
            return bpf_map_update_elem(&rcount, key, &one, BPF_NOEXIST);
        } else {
            const static char m[] = "This is NULL!";
            bpf_trace_printk(m, sizeof(m));

            return 1;
        }
    } else {
        (*count)++;
        return bpf_map_update_elem(&rcount, key, count, BPF_EXIST);
    }
}

SEC("uprobe/SSL_read")
int entry_ssl_read(void* ctx) {
    print_got_here("uprobe/SSL_read");

    __u32 cafe = (__u32) 0xbebecafe;
    count(&cafe, 0);

    return 0;
}

SEC("uretprobe/SSL_read")
int ret_ssl_read(void* ctx) {
    print_got_here("uretprobe/SSL_read");

    __u32 cafe = (__u32) 0xbebecafe;
    count(&cafe, 1);

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";