package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bpf probe.c -- -I/usr/include/bpf -O2 -g

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/net/http2/hpack"
)

const libSslPath = "/usr/lib/x86_64-linux-gnu/libssl.so.3"

// --- STRUTTURE DATI ---
// Replica strutture del codice C
type tlsDataEvent struct {
	Pid  uint32
	Uid  uint32
	Gid  uint32
	Len  uint32
	Comm [16]byte
	Data [400]byte
}

// Definizione struttura per il logging in JSON
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Category  string `json:"category"`
	Pid       uint32 `json:"pid"`
	Uid       uint32 `json:"uid"`
	Command   string `json:"command"`
	Message   string `json:"message"`
	Evidence  string `json:"evidence,omitempty"`
}

// Struttura per calcolare la statistica di varianza delle richieste per anomalia di beaconing
type BeaconTracker struct {
	LastSeen  time.Time
	Intervals []float64
	Count     int
}

func main() {
	// Aumento memoria allocabile in RAM
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Memlock error: %v", err)
	}

// Caricamento Oggetti eBPF
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Load objects error: %v", err)
	}
	defer objs.Close()

	// Attacco Uprobe
	ex, err := link.OpenExecutable(libSslPath)
	if err != nil {
		log.Fatalf("Open executable error: %v", err)
	}
	up, err := ex.Uprobe("SSL_write", objs.ProbeSslWrite, nil)
	if err != nil {
		log.Fatalf("Uprobe error: %v", err)
	}
	defer up.Close()

	// Definizione del file su cui loggare i dati in JSON
	logFileName := "http_security_events.json"
	logFile, err := os.OpenFile(logFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Impossibile creare file di log: %v", err)
	}
	defer logFile.Close()
	jsonEncoder := json.NewEncoder(logFile)

	fmt.Printf("🛡️  eBPF Sniffer ATTIVO su %s\n", libSslPath)
	fmt.Printf("📝 Logging attivo su: %s\n", logFileName)

	rd, err := ringbuf.NewReader(objs.TlsEvents)
	if err != nil {
		log.Fatalf("Ringbuf reader error: %v", err)
	}
	defer rd.Close()

	// Mappatura Magig Bytes
	contentTypes := make(map[uint32]string)
	decoders := make(map[uint32]*hpack.Decoder)
	
	// "UID:COMM" per tracciare il comportamento dell'utente/comando
	beaconMap := make(map[string]*BeaconTracker)

	// --- LOGGING ---
	// Funzione per il logging su file delle sole anomalie
	logEvent := func(pid, uid uint32, comm, level, category, msg, evidence string) {
		entry := LogEntry{
			Timestamp: time.Now().Format(time.RFC3339),
			Level:     level,
			Category:  category,
			Pid:       pid,
			Uid:       uid,
			Command:   comm,
			Message:   msg,
			Evidence:  evidence,
		}
		jsonEncoder.Encode(entry)

		if level == "CRITICAL" {
			fmt.Printf("    [!!!] ☠️  %s: %s\n", category, msg)
			if evidence != "" {
				fmt.Printf("          Evidence: %s\n", evidence)
			}
		} else if level == "WARNING" {
			fmt.Printf("    [!!!] ⚠️  %s: %s\n", category, msg)
		}
	}

	// --- BEACONING DETECTION ---
	checkBeaconing := func(pid, uid uint32, comm, path string) {
		// Whitelist
		exts := []string{".css", ".js", ".jpg", ".png", ".gif", ".ts", ".m4s", ".mp4", ".woff", ".ico"}
		for _, ext := range exts {
			if strings.HasSuffix(path, ext) {
				return
			}
		}

		// Chiave UID:COMM per bypassare problema cambio PID
		mapKey := fmt.Sprintf("%d:%s", uid, comm)
		now := time.Now()
		tracker, exists := beaconMap[mapKey]

		if !exists {
			beaconMap[mapKey] = &BeaconTracker{LastSeen: now, Intervals: make([]float64, 0, 10), Count: 1}
			return
		}

		delta := now.Sub(tracker.LastSeen).Seconds()

		// Reset timeout (30s)
		// Se passa troppo tempo resettiamo. Non resettiamo su nuova connessione!
		if delta > 30.0 {
			beaconMap[mapKey] = &BeaconTracker{LastSeen: now, Intervals: make([]float64, 0, 10), Count: 1}
			return
		}

		tracker.LastSeen = now
		tracker.Count++

		if delta < 0.1 {
			return
		} // Ignora burst

		if len(tracker.Intervals) >= 10 {
			tracker.Intervals = tracker.Intervals[1:]
		}
		tracker.Intervals = append(tracker.Intervals, delta)

		// Analisi Statistica per identificazione beaconing
		if len(tracker.Intervals) >= 5 {
			var sum, mean, variance, stdDev float64
			// Calcolo media
			for _, v := range tracker.Intervals {
				sum += v
			}
			mean = sum / float64(len(tracker.Intervals))

			// Calcolo varianza
			for _, v := range tracker.Intervals {
				variance += math.Pow(v-mean, 2)
			}
			variance = variance / float64(len(tracker.Intervals))
			stdDev = math.Sqrt(variance)

			// Calcolo coefficiente di variazione
			cv := 0.0
			if mean > 0 {
				cv = stdDev / mean
			}

			//Soglia
			if (stdDev < 0.2 || cv < 0.5) && mean > 0.5 {
				evidence := fmt.Sprintf("Path: %s | Avg: %.2fs | Jitter: %.4fs | CV: %.2f", path, mean, stdDev, cv)
				logEvent(pid, uid, comm, "CRITICAL", "BEACONING", "Rilevato traffico robotico periodico (C2 Heartbeat)", evidence)
				tracker.Intervals = make([]float64, 0, 10)
			}
		}
	}

	// --- BASE64 CHECK ---
	isSuspiciousBase64 := func(s string) bool {
		if len(s) < 8 || strings.Contains(s, " ") {
			return false
		}
		_, err := base64.StdEncoding.DecodeString(s)
		return err == nil
	}

	// --- CONTENT ANALYSIS ---
	checkContentMismatch := func(pid, uid uint32, comm, declaredType string, body []byte) {
		if len(body) < 4 {
			return
		}
		ct := strings.ToLower(declaredType)
		mismatch := false
		if strings.Contains(ct, "image/jpeg") || strings.Contains(ct, "image/jpg") {
			if body[0] != 0xFF || body[1] != 0xD8 || body[2] != 0xFF {
				mismatch = true
			}
		} else if strings.Contains(ct, "application/pdf") {
			if string(body[:4]) != "%PDF" {
				mismatch = true
			}
		} else if strings.Contains(ct, "image/png") {
			if body[0] != 0x89 || body[1] != 0x50 || body[2] != 0x4E || body[3] != 0x47 {
				mismatch = true
			}
		}

		if mismatch {
			evidence := fmt.Sprintf("Expected: %s | Actual Hex: %X %X %X %X", ct, body[0], body[1], body[2], body[3])
			logEvent(pid, uid, comm, "WARNING", "SPOOFING", "Content-Type non corrispondente", evidence)
		}

		isSafeType := strings.Contains(ct, "text/") || strings.Contains(ct, "json") || strings.Contains(ct, "xml") || strings.Contains(ct, "image/")
		if isSafeType {
			if body[0] == 0x7F && body[1] == 0x45 && body[2] == 0x4C && body[3] == 0x46 {
				logEvent(pid, uid, comm, "CRITICAL", "MALWARE", "Eseguibile Linux (ELF) nascosto", "MagicBytes: .ELF")
			}
			if body[0] == 0x4D && body[1] == 0x5A {
				logEvent(pid, uid, comm, "CRITICAL", "MALWARE", "Eseguibile Windows (EXE/DLL) nascosto", "MagicBytes: MZ")
			}
			if body[0] == 0x23 && body[1] == 0x21 {
				logEvent(pid, uid, comm, "CRITICAL", "MALWARE", "Script Shell/Bash nascosto", "MagicBytes: #!")
			}
		}
	}

	// Funzione principale
	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				continue
			}

			var event tlsDataEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				continue
			}

			// Variabile per mantenere meta dati dimensione pacchetto
			realLen := event.Len
			commName := string(bytes.TrimRight(event.Comm[:], "\x00"))

			if event.Len > 400 {
				event.Len = 400
			}
			payload := event.Data[:event.Len]
			sPayload := string(payload)

			fmt.Printf("\n--- [PID: %d | COMM: %s | UID: %d] (Real Len: %d | Buffered: %d) ---\n",
				event.Pid, commName, event.Uid, realLen, event.Len)

			// PACKETS OVER THRESHOLD (>400Bytes)
			if realLen > 2000 {
				isStuffing := false
				protocol := "UNKNOWN"

				// Caso A: HTTP/2
				if len(payload) >= 9 && payload[3] == 0x01 {
					isStuffing = true
					protocol = "HTTP/2 (Frame HEADERS)"
				}
				// Caso B: HTTP/1.1
				if strings.HasPrefix(sPayload, "GET ") || strings.HasPrefix(sPayload, "POST ") ||
					strings.HasPrefix(sPayload, "HEAD ") || strings.HasPrefix(sPayload, "PUT ") {
					isStuffing = true
					protocol = "HTTP/1.1 (Text Headers)"
				}
				// Caso C: PRI * HTTP/2.0
				if strings.HasPrefix(sPayload, "PRI * HTTP/2.0") {
					isStuffing = true
					protocol = "HTTP/2 (Connection Setup + Huge Headers)"
				}

				if isStuffing {
					evidence := fmt.Sprintf("Real Size: %d bytes (Truncated to 400) | Protocol: %s", realLen, protocol)
					logEvent(event.Pid, event.Uid, commName, "WARNING", "STUFFING", "Rilevato Header Set Enorme (Blind Detection)", evidence)
				}
			}

			// HTTP/1.1 PARSER
			if strings.HasPrefix(sPayload, "GET ") || strings.HasPrefix(sPayload, "POST ") ||
				strings.HasPrefix(sPayload, "PUT ") || strings.HasPrefix(sPayload, "DELETE ") ||
				strings.HasPrefix(sPayload, "HEAD ") || strings.HasPrefix(sPayload, "OPTIONS ") {
				
				fmt.Printf("[HTTP/1.1 Analysis]:\n")
				
				lines := strings.Split(sPayload, "\n")
				
				// Analisi URL (per Beaconing)
				if len(lines) > 0 {
					reqParts := strings.Split(lines[0], " ")
					if len(reqParts) >= 2 {
						method := reqParts[0]
						path := reqParts[1]
						fmt.Printf("    📡 Method: %s | Path: %s\n", method, path)
						
						// Attiva il rilevamento Beaconing anche su HTTP/1.1
						checkBeaconing(event.Pid, event.Uid, commName, path)
					}
				}

				// Analisi Headers
				bodyStartIndex := -1
				for i, line := range lines {
					if i == 0 { continue } // Salta Request Line
					cleanLine := strings.TrimSpace(line)
					
					// Rileva fine headers (riga vuota)
					if cleanLine == "" {
						bodyStartIndex = i + 1
						break 
					}

					// Parsing Header Key: Value
					parts := strings.SplitN(cleanLine, ":", 2)
					if len(parts) == 2 {
						key := strings.ToLower(strings.TrimSpace(parts[0]))
						val := strings.TrimSpace(parts[1])
						valLen := len(val)

						fmt.Printf("    🔹 %s: %s\n", key, val)

						// Check Content-Type (salviamo per eventuale body check)
						if key == "content-type" {
							contentTypes[event.Pid] = val
						}

						// Check Stuffing Granulare (HTTP/1.1)
						threshold := 250
						if key == "cookie" || key == "authorization" || key == "user-agent" {
							threshold = 1500 // Soglia più alta per questi
						}
						
						if valLen > threshold {
							evidence := fmt.Sprintf("Size: %d bytes (Threshold: %d)", valLen, threshold)
							logEvent(event.Pid, event.Uid, commName, "WARNING", "STUFFING", fmt.Sprintf("Header HTTP/1 '%s' troppo grande", key), evidence)
						}

						// Check Base64
						if isSuspiciousBase64(val) && key != "cookie" && key != "authorization" {
							dec, _ := base64.StdEncoding.DecodeString(val)
							limit := len(dec)
							if limit > 40 { limit = 40 }
							decodedSnippet := string(dec)[:limit]
							logEvent(event.Pid, event.Uid, commName, "WARNING", "OBFUSCATION", fmt.Sprintf("Base64 sospetto in header HTTP/1 '%s'", key), decodedSnippet)
						}
					}
				}

				// Analisi Body (se visibile nel buffer)
				// Se abbiamo trovato la fine degli header e il buffer non è finito, c'è un body.
				if bodyStartIndex > 0 && bodyStartIndex < len(lines) {
					// Ricostruiamo il body unendo le righe restanti
					bodyStr := strings.Join(lines[bodyStartIndex:], "\n")
					bodyBytes := []byte(bodyStr)
					
					if len(bodyBytes) > 0 {
						fmt.Printf("--> 🟢 BODY (HTTP/1 Preview): %s\n", string(bodyBytes))
						declaredType, known := contentTypes[event.Pid]
						if known {
							checkContentMismatch(event.Pid, event.Uid, commName, declaredType, bodyBytes)
						}
					}
				}
				fmt.Println("------------------")
				continue // Passa al prossimo evento, abbiamo già gestito HTTP/1
			}

			// HTTP/2 PARSER (HPACK)
			securityCallback := func(f hpack.HeaderField) {
				name := strings.ToLower(f.Name)
				val := f.Value
				length := len(val)

				if name == ":path" {
					checkBeaconing(event.Pid, event.Uid, commName, val)
				}
				if name == "content-type" {
					contentTypes[event.Pid] = val
					fmt.Printf("    📝 Content-Type: %s\n", val)
				}

				threshold := 250
				if name == "cookie" || name == "authorization" {
					threshold = 1500
				}
				if length > threshold {
					evidence := fmt.Sprintf("Size: %d bytes (Threshold: %d)", length, threshold)
					logEvent(event.Pid, event.Uid, commName, "WARNING", "STUFFING", fmt.Sprintf("Header '%s' troppo grande", name), evidence)
				}

				if isSuspiciousBase64(val) && (name != "authorization" && name != "cookie") {
					dec, _ := base64.StdEncoding.DecodeString(val)
					limit := len(dec)
					if limit > 40 {
						limit = 40
					}
					decodedSnippet := string(dec)[:limit]
					logEvent(event.Pid, event.Uid, commName, "WARNING", "OBFUSCATION", fmt.Sprintf("Base64 sospetto in header '%s'", name), decodedSnippet)
				}
				fmt.Printf("    🔹 %s: %s\n", name, val)
			}

			decoder, exists := decoders[event.Pid]
			if !exists {
				decoder = hpack.NewDecoder(4096, securityCallback)
				decoders[event.Pid] = decoder
			}

			if len(payload) >= 24 && strings.HasPrefix(sPayload, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
				fmt.Println(">>> RESET HTTP/2 CONTEXT <<<")
				decoders[event.Pid] = hpack.NewDecoder(4096, securityCallback)
				delete(contentTypes, event.Pid)
				payload = payload[24:]
			}

			currentPayload := payload
			for len(currentPayload) >= 9 {
				frameLen := uint32(currentPayload[0])<<16 | uint32(currentPayload[1])<<8 | uint32(currentPayload[2])
				frameType := currentPayload[3]

				if uint32(len(currentPayload)) < 9+frameLen || frameLen > 10000 {
					break
				}
				if frameType == 1 && frameLen > 0 { // HEADER
					frameData := currentPayload[9 : 9+frameLen]
					if activeDecoder, ok := decoders[event.Pid]; ok {
						activeDecoder.Write(frameData)
					}
				}
				if frameType == 0 && frameLen > 0 { // DATA
					bodyData := currentPayload[9 : 9+frameLen]
					fmt.Printf("--> 🟢 BODY: %s\n", string(bodyData))
					declaredType, known := contentTypes[event.Pid]
					if known {
						checkContentMismatch(event.Pid, event.Uid, commName, declaredType, bodyData)
					}
				}
				currentPayload = currentPayload[9+frameLen:]
			}
			fmt.Println("---------------------------------------------------")
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
}
