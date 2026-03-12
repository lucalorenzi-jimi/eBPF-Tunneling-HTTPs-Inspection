package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// Handler generico per la root /
// Utile per test di connettività base (es. Nikto scan, Curl semplice)
func rootHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "200 OK - Target Server is running\n")
	fmt.Fprintf(w, "Protocol: %s\n", r.Proto)
	fmt.Fprintf(w, "Method: %s\n", r.Method)
	
	// Log minimo a terminale
	fmt.Printf("[%s] Richiesta ricevuta su / (%s)\n", time.Now().Format(time.TimeOnly), r.Proto)
}

// Handler per testare l'UPLOAD
// Per Magic Bytes check, Content-Type Spoofing
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	// Leggiamo il corpo della richiesta per generare traffico effettivo
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Errore lettura body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	contentType := r.Header.Get("Content-Type")
	size := len(body)

	// Logghiamo cosa è arrivato
	fmt.Printf("[%s] 📡 UPLOAD ricevuto | Size: %d bytes | Type: %s\n", 
		time.Now().Format(time.TimeOnly), size, contentType)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status": "received", "size": %d, "type": "%s"}`, size, contentType)
}

func main() {
	// 1. Configurazione Rotte
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/upload", uploadHandler)

	// 2. Avvio Server HTTP in CHIARO (Porta 8000) - PER SURICATA E SNORT
	go func() {
		fmt.Println("⚠️  Server HTTP (Chiaro) in ascolto su :8000 (Per Test NIDS tradizionali)")
		if err := http.ListenAndServe(":8000", nil); err != nil {
			log.Fatalf("Errore HTTP: %v", err)
		}
	}()

	// 3. Avvio Server HTTPS CRIPTATO (Porta 8443) - PER EBPF
	fmt.Println("🔒 Server HTTPS (Criptato) in ascolto su :8443 (Per Test eBPF)")
	
	// Assicurati di avere server.crt e server.key nella stessa cartella
	err := http.ListenAndServeTLS(":8443", "server.crt", "server.key", nil)
	if err != nil {
		log.Fatal("Errore HTTPS: ", err)
	}
}
