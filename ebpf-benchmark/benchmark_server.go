package main

import (
	"fmt"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	// Risposta minima per non stressare troppo l'I/O, ma sufficiente per testare HTTP/2
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "200 OK - Test eBPF")
}

func main() {
	http.HandleFunc("/", handler)
	fmt.Println("Server HTTPS Vittima in ascolto su :8443")
	// Usiamo i certificati generati
	log.Fatal(http.ListenAndServeTLS(":8443", "server.crt", "server.key", nil))
}
