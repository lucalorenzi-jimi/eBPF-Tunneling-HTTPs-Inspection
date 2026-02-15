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

SEC("uprobe/SSL_write")
int probe_ssl_write(struct pt_regs *ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    // Raccolta UID e GID
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid & 0xFFFFFFFF;
    u32 gid = current_uid_gid >> 32;

    // Lettura parametri di SSL_write(ssl, buf, num)
    // 2° argomento = buffer, 3° argomento = lunghezza
    void *buf_ptr = (void *)PT_REGS_PARM2(ctx);
    u32 len = (u32)PT_REGS_PARM3(ctx);

    if (len <= 0) return 0;

    // Allocazione spazio nel RingBuffer
    struct tls_data_event_t *event;
    event = bpf_ringbuf_reserve(&tls_events, sizeof(*event), 0);
    if (!event) {
        return 0; // Buffer pieno o errore allocazione
    }

    // Salvataggio dati nella struttura
    event->pid = pid;
    event->uid = uid;
    event->gid = gid;
    event->len = len;
    
    // Cattura nome del comando (es. "curl")
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Limitiamo la lunghezza dati
    if (len > 400) len = 400;
    
    // Copia dati dal buffer utente al kernel
    bpf_probe_read_user(event->data, len, buf_ptr);

    // Invio l'evento
    bpf_ringbuf_submit(event, 0);

    return 0;
}
