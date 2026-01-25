package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// CONFIGURAZIONE TARGET
const (
	TargetHTTPS = "https://localhost:8443"
	TargetHTTP  = "http://localhost:8000"
	TargetHost  = "localhost"
	TargetPort  = "8000"
)

// Funzione helper per lanciare CURL
func runCurl(target, method, endpoint string, headers map[string]string, dataFile string, proto string, desc string) {
	fmt.Printf("   👉 Invio a %s... ", target)
	args := []string{"-k", "-s", "-o", "/dev/null", "-X", method}

	if proto == "h2" {
		args = append(args, "--http2")
	} else {
		args = append(args, "--http1.1")
	}

	args = append(args, "-H", "User-Agent: Mozilla/5.0 (X11; Linux x86_64) eBPF-Thesis-Agent/1.0")
	for k, v := range headers {
		args = append(args, "-H", fmt.Sprintf("%s: %s", k, v))
	}

	if dataFile != "" {
		args = append(args, "--data-binary", "@"+dataFile)
	}

	args = append(args, target+endpoint)
	cmd := exec.Command("curl", args...)
	err := cmd.Run()

	if err != nil {
		fmt.Printf("❌ Errore: %v\n", err)
	} else {
		fmt.Printf("✅ Inviato (%s)\n", desc)
	}
}

// NUOVA FUNZIONE: Invia pacchetto RAW TCP (Replica esatta di Netcat)
// Serve per aggirare le idiosincrasie di Curl su regole Suricata molto rigide
func runRawCVE(host, port string) {
	fmt.Printf("\n⚔️  TEST: CVE-2024-1212 (RAW TCP Socket) [Chiaro/Suricata]\n")
	fmt.Printf("   👉 Connessione diretta a %s:%s... ", host, port)

	conn, err := net.Dial("tcp", host+":"+port)
	if err != nil {
		fmt.Printf("❌ Errore connessione: %v\n", err)
		return
	}
	defer conn.Close()

	// Costruiamo il payload ESATTAMENTE come nel test 'nc' che ha funzionato.
	// URI: 35 chars esatti.
	// Header Authorization: Spaziatura perfetta.
	payload := "GET /access/set?param=enableapi&value=1 HTTP/1.1\r\n" +
		"Host: " + host + ":" + port + "\r\n" +
		"Authorization: Basic O2NhdCAvZXRjL3Bhc3N3ZDs=\r\n" +
		"User-Agent: ManualTest\r\n" +
		"Connection: close\r\n" +
		"\r\n"

	_, err = fmt.Fprintf(conn, payload)
	if err != nil {
		fmt.Printf("❌ Errore invio: %v\n", err)
		return
	}
	
	// Leggiamo un po' della risposta per assicurarci che sia partita
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, _ = conn.Read(buf) // Ignoriamo errori di timeout, ci basta aver inviato

	fmt.Println("✅ Inviato (Byte-perfect Payload)")
	time.Sleep(500 * time.Millisecond)
}

// Wrapper per eseguire il test su entrambi i target
func runDualTest(name, method, endpoint string, headers map[string]string, dataFile, proto string) {
	fmt.Printf("\n⚔️  TEST: %s [%s]\n", name, proto)
	// 1. HTTPS (eBPF)
	runCurl(TargetHTTPS, method, endpoint, headers, dataFile, proto, "Criptato/eBPF")
	// 2. HTTP (Suricata)
	runCurl(TargetHTTP, method, endpoint, headers, dataFile, "h1", "Chiaro/Suricata")
	
	time.Sleep(500 * time.Millisecond)
}

// Verifica esistenza file
func checkFilesExist(files []string) {
	missing := false
	for _, f := range files {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			fmt.Printf("❌ ERRORE CRITICO: Manca il file '%s'!\n", f)
			missing = true
		}
	}
	if missing {
		fmt.Println("⚠️  Esegui i comandi manuali per creare i file mancanti prima di lanciare il test.")
		os.Exit(1)
	}
}

func main() {
	fmt.Println("🚀 AVVIO TEST SUITE PERSISTENTE (EICAR Auto-Clean)")
	fmt.Println("--------------------------------------------------")

	// 1. GESTIONE FILE
	
	// Generiamo EICAR
	eicarString := `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
	os.WriteFile("eicar.com", []byte(eicarString), 0644)

	// Lista file attesi (inclusi quelli creati da te con printf)
	payloads := []string{
		"innocent.txt", 
		"finto_exploit.sh", 
		"finto_malware.bin", 
		"eicar.com", 
		"finto_windows.exe",  
		"finto_archivio.zip",
	}
	
	checkFilesExist(payloads)
	fmt.Println("✅ Tutti i file payload sono presenti.")

	// --- 2. TEST STANDARD ---
	runDualTest("Parsing HTTP/1.1", "GET", "/", nil, "", "h1")
	runDualTest("Parsing HTTP/2 + HPACK", "GET", "/", nil, "", "h2")
	
	// --- 3. HEADER STUFFING ---
	junkHeader := strings.Repeat("A", 3000)
	stuffingHeaders := map[string]string{"X-Stuffing-Data": junkHeader}
	runDualTest("Stuffing HTTP/1.1 (Huge Header)", "GET", "/", stuffingHeaders, "", "h1")
	runDualTest("Stuffing HTTP/2 (Header Frame)", "GET", "/", stuffingHeaders, "", "h2")
	
	// --- 4. TEST HEADER STUFFING (Violazione Limite Suricata) ---
	// Il default di Suricata è 32KB (32768 bytes).
	// Creiamo un header di 40KB per forzare un'anomalia di protocollo.
	// Nota: Curl potrebbe lamentarsi "Argument list too long" se esageriamo, ma 40KB dovrebbe reggerli.
	junkSize := 40000 
	fmt.Printf("\nGenerating %d bytes header...\n", junkSize)
	hugeHeader := strings.Repeat("A", junkSize)
	stuffingHeaders2 := map[string]string{"X-Stuffing": hugeHeader}
	
	runDualTest("Header Stuffing (40KB - Over Limit)", "GET", "/", stuffingHeaders2, "", "h1")
	
	// --- 5. OFFUSCAZIONE BASE64 ---
	base64Headers := map[string]string{"X-Exploit-Cmd": "Y2F0IC9ldGMvcGFzc3dk"}
	runDualTest("Offuscazione Base64 (Header)", "GET", "/", base64Headers, "", "h2")
	
	// --- 6. TEST BASE64 (Simulazione CVE-2024-1212) ---
	// La regola sid:2056142 cerca:
	// - URI: /access/set?param=enableapi&value=1
	// - Header: Authorization: Basic ...
	// - Decoded: ;<qualcosa>;
	// Payload: ";cat /etc/passwd;" -> Base64: "O2NhdCAvZXRjL3Bhc3N3ZDs="
	cveURI := "/access/set?param=enableapi&value=1"
	cveHeaders := map[string]string{
		"Authorization": "Basic O2NhdCAvZXRjL3Bhc3N3ZDs=",
	}
	fmt.Printf("\n⚔️  TEST: CVE-2024-1212 [Criptato/eBPF]\n")
	runCurl(TargetHTTPS, "GET", cveURI, cveHeaders, "", "h2", "Criptato/eBPF")
	runRawCVE(TargetHost, TargetPort)

	// --- 7. TEST EICAR ---
	runDualTest("EICAR Binary Upload", "POST", "/upload", map[string]string{"Content-Type": "application/octet-stream"}, "eicar.com", "h1")

	// --- 8. CONTENT TYPE SPOOFING & MALWARE CUSTOM ---
	
	// A. Spoofing Generico (Txt -> PNG)
	spoofPngHeaders := map[string]string{"Content-Type": "image/png"}
	runDualTest("Spoofing: Txt spacciato per PNG", "POST", "/upload", spoofPngHeaders, "innocent.txt", "h1")

	// B. Script Injection (Bash -> PDF)
	spoofPdfHeaders := map[string]string{"Content-Type": "application/pdf"}
	runDualTest("Malware: Bash spacciato per PDF", "POST", "/upload", spoofPdfHeaders, "finto_exploit.sh", "h1")
	
	// C. Windows EXE spacciato per immagine
	runDualTest("Malware: EXE spacciato per PNG", "POST", "/upload", map[string]string{"Content-Type": "image/png"}, "finto_windows.exe", "h1")

	// D. ZIP Archive spacciato per PDF
	runDualTest("Spoofing: ZIP spacciato per PDF", "POST", "/upload", map[string]string{"Content-Type": "application/pdf"}, "finto_archivio.zip", "h1")

	// E. Binary Malware (ELF -> JPEG)
	spoofJpgHeaders := map[string]string{"Content-Type": "image/jpeg"}
	runDualTest("Malware: ELF spacciato per JPEG", "POST", "/upload", spoofJpgHeaders, "finto_malware.bin", "h2")

	// Rimuoviamo SOLO l'Eicar. I file manuali (.exe, .zip, ecc) restano lì.
	os.Remove("eicar.com")
	
	fmt.Println("\n🏁 Test completati. EICAR rimosso.")
}
