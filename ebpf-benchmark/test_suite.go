package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// CONFIGURAZIONE TARGET
const (
	TargetHTTPS = "https://localhost:8443"
	TargetHTTP  = "http://localhost:8000"
)

// Funzione helper per lanciare CURL via terminale
// Usa OpenSSL (libssl.so) quindi è visibile a eBPF
func runCurl(target string, method string, endpoint string, headers map[string]string, dataFile string, forceProto string, description string) {
	fmt.Printf("   👉 Invio a %s... ", target)

	args := []string{"-k", "-s", "-o", "/dev/null", "-X", method}

	// Forzatura Protocollo
	if forceProto == "h2" {
		args = append(args, "--http2")
	} else {
		args = append(args, "--http1.1")
	}

	// Headers
	args = append(args, "-H", "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (Chrome/Test)")
	for k, v := range headers {
		args = append(args, "-H", fmt.Sprintf("%s: %s", k, v))
	}

	// Body (File esistente)
	if dataFile != "" {
		args = append(args, "--data-binary", fmt.Sprintf("@%s", dataFile))
	}

	args = append(args, target+endpoint)

	cmd := exec.Command("curl", args...)
	err := cmd.Run()

	if err != nil {
		fmt.Printf("❌ Errore: %v\n", err)
	} else {
		fmt.Printf("✅ Inviato (%s)\n", description)
	}
}

// Wrapper per eseguire il test su entrambi i target
func runDualTest(name string, method string, endpoint string, headers map[string]string, dataFile string, proto string) {
	fmt.Printf("\n⚔️  TEST: %s [%s]\n", name, proto)
	
	// 1. HTTPS (eBPF)
	runCurl(TargetHTTPS, method, endpoint, headers, dataFile, proto, "Criptato/eBPF")
	
	// 2. HTTP (Suricata)
	runCurl(TargetHTTP, method, endpoint, headers, dataFile, "h1", "Chiaro/Suricata")
	
	time.Sleep(500 * time.Millisecond) 
}

// Controlla che i file necessari esistano
func checkFilesExist(files []string) {
	missing := false
	for _, f := range files {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			fmt.Printf("❌ ERRORE CRITICO: Manca il file '%s' nella cartella!\n", f)
			missing = true
		}
	}
	if missing {
		fmt.Println("⚠️  Assicurati di avere 'innocent.txt', 'finto_exploit.sh' e il tuo 'finto_malware.bin' nella cartella.")
		os.Exit(1)
	}
}

func main() {
	fmt.Println("🚀 AVVIO TEST SUITE (File Statici)")
	fmt.Println("----------------------------------")

	// 1. Verifica preliminare dei payload
	// AGGIORNATO: Ora cerca finto_malware.bin invece di malware.elf
	payloads := []string{"innocent.txt", "finto_exploit.sh", "finto_malware.bin"}
	checkFilesExist(payloads)
	fmt.Println("✅ Tutti i file payload sono presenti.")

	// --- 1. PARSING PROTOCOLLI ---
	runDualTest("Parsing HTTP/1.1", "GET", "/", nil, "", "h1")
	runDualTest("Parsing HTTP/2 + HPACK", "GET", "/", nil, "", "h2")

	// --- 2. HEADER STUFFING ---
	junkHeader := strings.Repeat("A", 3000)
	stuffingHeaders := map[string]string{"X-Stuffing-Data": junkHeader}
	
	runDualTest("Stuffing HTTP/1.1 (Huge Header)", "GET", "/", stuffingHeaders, "", "h1")
	runDualTest("Stuffing HTTP/2 (Header Frame)", "GET", "/", stuffingHeaders, "", "h2")

	// --- 3. OFFUSCAZIONE BASE64 ---
	base64Headers := map[string]string{"X-Exploit-Cmd": "Y2F0IC9ldGMvcGFzc3dk"}
	runDualTest("Offuscazione Base64 (Header)", "GET", "/", base64Headers, "", "h2")

	// --- 4. CONTENT TYPE SPOOFING & MALWARE ---
	
	// A. Spoofing Generico (Txt -> PNG)
	spoofPngHeaders := map[string]string{"Content-Type": "image/png"}
	runDualTest("Spoofing: Txt spacciato per PNG", "POST", "/upload", spoofPngHeaders, "innocent.txt", "h1")

	// B. Script Injection (Bash -> PDF)
	spoofPdfHeaders := map[string]string{"Content-Type": "application/pdf"}
	runDualTest("Malware: Bash spacciato per PDF", "POST", "/upload", spoofPdfHeaders, "finto_exploit.sh", "h1")

	// C. Binary Malware (ELF -> JPEG)
	// AGGIORNATO: Usa il tuo finto_malware.bin
	spoofJpgHeaders := map[string]string{"Content-Type": "image/jpeg"}
	runDualTest("Malware: ELF spacciato per JPEG", "POST", "/upload", spoofJpgHeaders, "finto_malware.bin", "h2")

	fmt.Println("\n🏁 Test Completati.")
}
