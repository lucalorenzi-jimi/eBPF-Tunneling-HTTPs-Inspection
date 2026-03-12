package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os/exec"
	"time"
)

func main() {
	// 1. Configurazione dei parametri
	modePtr := flag.String("mode", "fixed", "Modalità: 'fixed', 'mixed', 'slow'")
	urlPtr := flag.String("url", "https://localhost:8443", "URL target")
	flag.Parse()

	// Inizializza il generatore casuale
	rand.Seed(time.Now().UnixNano())

	fmt.Printf("--- AVVIO ATTACCO (Wrapper curl): Modalità %s ---\n", *modePtr)
	fmt.Printf("Target: %s\n", *urlPtr)
	fmt.Println("Premi CTRL+C per fermare.")

	count := 0
	for {
		count++

		// 2. ESECUZIONE DELLA RICHIESTA TRAMITE CURL
		// 'exec' per lanciare curl, così usa la librerie OpenSSL
		// -k: ignora certificati (insecure)
		// -s: silent mode
		// -o /dev/null: butta via l'output del corpo
		cmd := exec.Command("curl", "-k", "-s", "-o", "/dev/null", *urlPtr)

		// Lancia il comando e aspetta che finisca
		err := cmd.Run()

		if err != nil {
			fmt.Printf("[Error] Richiesta #%d fallita: %v\n", count, err)
		} else {
			fmt.Printf("[Attacco] Richiesta #%d inviata tramite curl.\n", count)
		}

		// 3. LOGICA DI ATTESA
		var sleepTime time.Duration

		switch *modePtr {

		case "fixed": // SCENARIO 1: Attesa fissa: 2s"
			sleepTime = 2 * time.Second

		case "mixed": // SCENARIO 2: Jitter (1s - 3s)
			min := 1.0
			max := 3.0
			// Genera un tempo casuale
			randomSecs := min + rand.Float64()*(max-min)
			sleepTime = time.Duration(randomSecs * float64(time.Second))
			fmt.Printf("   -> Jitter: attesa di %.2fs\n", randomSecs)

		case "slow": // SCENARIO 3: Attesa fissa ma lunga (10s)
			sleepTime = 10 * time.Second

		default:
			sleepTime = 2 * time.Second
		}

		time.Sleep(sleepTime)
	}
}
