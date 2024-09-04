package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/sha3"
)

var (
	found     int64 // Number of found addresses
	generated int64 // Number of generated addresses
)

const batchSize = 1000 // Batch size for key generation

// generateBatch generates a batch of keys and checks them against the regular expression
func generateBatch(wg *sync.WaitGroup, re *regexp.Regexp, resultChan chan<- string) {
	var buffer bytes.Buffer
	buffer.Grow(100) // Pre-allocate memory for the buffer
	batch := make([]ed25519.PublicKey, batchSize)
	batchSecretKeys := make([]ed25519.PrivateKey, batchSize)

	for {
		// Generate a batch of keys
		for i := 0; i < batchSize; i++ {
			pub, priv, _ := ed25519.GenerateKey(nil)
			batch[i] = pub
			batchSecretKeys[i] = priv
		}
		atomic.AddInt64(&generated, batchSize)

		// Check generated keys
		for i, publicKey := range batch {
			buffer.Reset()
			onionAddress := encodePublicKey(publicKey, &buffer)
			if re.MatchString(onionAddress) {
				resultChan <- onionAddress
				go save(onionAddress, publicKey, expandSecretKey(batchSecretKeys[i])) // Asynchronous saving
				atomic.AddInt64(&found, 1)
				wg.Done()
			}
		}
	}
}

// expandSecretKey expands the secret key to 64 bytes
func expandSecretKey(secretKey ed25519.PrivateKey) [64]byte {
	hash := sha512.Sum512(secretKey[:32])
	hash[0] &= 248
	hash[31] &= 127
	hash[31] |= 64
	return hash
}

// encodePublicKey encodes the public key into an onion address
func encodePublicKey(publicKey ed25519.PublicKey, buffer *bytes.Buffer) string {
	buffer.Write([]byte(".onion checksum"))
	buffer.Write(publicKey)
	buffer.WriteByte(0x03)
	checksum := sha3.Sum256(buffer.Bytes())
	buffer.Reset()
	buffer.Write(publicKey)
	buffer.Write(checksum[:2])
	buffer.WriteByte(0x03)
	return strings.ToLower(base32.StdEncoding.EncodeToString(buffer.Bytes()))
}

// save stores the generated keys and address in files
func save(onionAddress string, publicKey ed25519.PublicKey, secretKey [64]byte) {
	os.MkdirAll(onionAddress, 0700)
	secretKeyFile := append([]byte("== ed25519v1-secret: type0 ==\x00\x00\x00"), secretKey[:]...)
	os.WriteFile(onionAddress+"/hs_ed25519_secret_key", secretKeyFile, 0600)
	publicKeyFile := append([]byte("== ed25519v1-public: type0 ==\x00\x00\x00"), publicKey...)
	os.WriteFile(onionAddress+"/hs_ed25519_public_key", publicKeyFile, 0600)
	os.WriteFile(onionAddress+"/hostname", []byte(onionAddress+".onion\n"), 0600)
}

// printStats outputs generation statistics every 5 seconds
func printStats(startTime time.Time) {
	for range time.Tick(5 * time.Second) {
		currentFound := atomic.LoadInt64(&found)
		currentGenerated := atomic.LoadInt64(&generated)
		elapsedSeconds := time.Since(startTime).Seconds()
		addressesPerSecond := float64(currentGenerated) / elapsedSeconds
		fmt.Printf("Progress: %d found, %d generated, %.2f addresses/sec\n",
			currentFound, currentGenerated, addressesPerSecond)
	}
}

func main() {
	// Check command-line arguments
	if len(os.Args) != 3 {
		fmt.Println("Usage: program <regex> <num_addresses>")
		os.Exit(1)
	}

	// Compile the regular expression
	re, err := regexp.Compile(os.Args[1])
	if err != nil {
		fmt.Println("Invalid regex:", err)
		os.Exit(1)
	}

	// Parse the number of addresses
	numAddresses, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Println("Invalid number of addresses:", err)
		os.Exit(1)
	}

	var wg sync.WaitGroup
	wg.Add(numAddresses)
	resultChan := make(chan string, numAddresses)

	// Start a goroutine to print statistics
	go printStats(time.Now())

	// Start goroutines for address generation
	for i := 0; i < runtime.NumCPU(); i++ {
		go generateBatch(&wg, re, resultChan)
	}

	// Goroutine to print found addresses
	go func() {
		for address := range resultChan {
			fmt.Println(address)
		}
	}()

	wg.Wait()
	close(resultChan)
}
