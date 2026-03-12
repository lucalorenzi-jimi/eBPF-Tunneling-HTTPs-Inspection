//go:build ignore
#include "vmlinux.h" 
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// Struttura per raccolta dati PID, UID, GID e command
struct tls_data_event_t {
    u32 pid;		// Process ID
    u32 uid;        // User ID 
    u32 gid;        // Group ID
    u32 len;        // Lunghezza del payload catturato
    char comm[16];  // Nome del comando
    u8 data[400];   // Buffer del payload
};

// 1. Definizione RINGBUF 
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB di buffer condiviso
} tls_events SEC(".maps");

void get_event_info(const void *buf, int num, struct tls_data_event_t *event) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u64 current_uid_gid = bpf_get_current_uid_gid();

    event->pid = current_pid_tgid >> 32;
    event->uid = current_uid_gid & 0xFFFFFFFF;
    event->gid = current_uid_gid >> 32;

    // Cattura nome del comando (es. "curl")
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    event->len = num;

    // Limitiamo la lunghezza dati
    if (event->len > 400) event->len = 400;
    
    // Copia dati dal buffer utente al kernel
    bpf_probe_read_user(event->data, event->len, buf);
}

SEC("uprobe/SSL_write")
int BPF_UPROBE(probe_ssl_write, void *s, const void *buf, int num) {
    // You have BOTH:
    //  - struct pt_regs *ctx  (implicitly provided by the macro expansion)
    //  - params               (extracted from ctx according to ABI)

    if (num <= 0) return 0;

    // Allocazione spazio nel RingBuffer
    struct tls_data_event_t *event;
    event = bpf_ringbuf_reserve(&tls_events, sizeof(*event), 0);
    if (!event) {
        return 0; // Buffer pieno o errore allocazione
    }

    get_event_info(buf, num, event);

    // Invio l'evento
    bpf_ringbuf_submit(event, 0);

    return 0;
}
