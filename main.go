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

const batchSize = 10000 // Increased batch size for better performance

// Preallocate buffers for each goroutine
var bufferPool = sync.Pool{
	New: func() interface{} {
		buffer := new(bytes.Buffer)
		buffer.Grow(100)
		return buffer
	},
}

// generateBatch generates a batch of keys and checks them against the regular expressions
func generateBatch(wg *sync.WaitGroup, regexps []*regexp.Regexp, resultChan chan<- string, saveWg *sync.WaitGroup) {
	buffer := bufferPool.Get().(*bytes.Buffer)
	defer bufferPool.Put(buffer)

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
			onionAddress := encodePublicKey(publicKey, buffer)
			for _, re := range regexps {
				if re.MatchString(onionAddress) {
					resultChan <- onionAddress
					saveWg.Add(1)
					go save(onionAddress, publicKey, expandSecretKey(batchSecretKeys[i]), saveWg)
					atomic.AddInt64(&found, 1)
					wg.Done()
					break
				}
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
func save(onionAddress string, publicKey ed25519.PublicKey, secretKey [64]byte, wg *sync.WaitGroup) {
	defer wg.Done()
	err := os.MkdirAll(onionAddress, 0700)
	if err != nil {
		fmt.Printf("Error creating directory %s: %v\n", onionAddress, err)
		return
	}
	secretKeyFile := append([]byte("== ed25519v1-secret: type0 ==\x00\x00\x00"), secretKey[:]...)
	err = os.WriteFile(onionAddress+"/hs_ed25519_secret_key", secretKeyFile, 0600)
	if err != nil {
		fmt.Printf("Error writing secret key file for %s: %v\n", onionAddress, err)
		return
	}
	publicKeyFile := append([]byte("== ed25519v1-public: type0 ==\x00\x00\x00"), publicKey...)
	err = os.WriteFile(onionAddress+"/hs_ed25519_public_key", publicKeyFile, 0600)
	if err != nil {
		fmt.Printf("Error writing public key file for %s: %v\n", onionAddress, err)
		return
	}
	err = os.WriteFile(onionAddress+"/hostname", []byte(onionAddress+".onion\n"), 0600)
	if err != nil {
		fmt.Printf("Error writing hostname file for %s: %v\n", onionAddress, err)
		return
	}
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
	if len(os.Args) < 2 {
		fmt.Println("Usage: program <regex1> [<regex2> ...] [<num_addresses>]")
		os.Exit(1)
	}

	// Parse and compile regular expressions
	var regexps []*regexp.Regexp
	numAddresses := 1
	var err error

	for i := 1; i < len(os.Args); i++ {
		if i == len(os.Args)-1 {
			// Check if the last argument is a number
			numAddresses, err = strconv.Atoi(os.Args[i])
			if err == nil {
				break
			}
		}
		re, err := regexp.Compile(os.Args[i])
		if err != nil {
			fmt.Printf("Invalid regex '%s': %v\n", os.Args[i], err)
			os.Exit(1)
		}
		regexps = append(regexps, re)
	}

	if len(regexps) == 0 {
		fmt.Println("At least one valid regex is required")
		os.Exit(1)
	}

	var wg sync.WaitGroup
	var saveWg sync.WaitGroup
	if numAddresses < 1 {
		numAddresses = 1
	}
	wg.Add(numAddresses)
	resultChan := make(chan string, numAddresses)

	// Start a goroutine to print statistics
	go printStats(time.Now())

	// Start goroutines for address generation
	numCPU := runtime.NumCPU()
	for i := 0; i < numCPU; i++ {
		go generateBatch(&wg, regexps, resultChan, &saveWg)
	}

	// Goroutine to print found addresses
	go func() {
		for address := range resultChan {
			fmt.Println(address)
		}
	}()

	wg.Wait()
	close(resultChan)

	// Wait for all save operations to complete
	saveWg.Wait()
}
