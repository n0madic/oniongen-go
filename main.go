package main

import (
	"crypto/ed25519"
	"encoding/base32"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/sha3"
)

var (
	found     int64 // Number of found addresses
	generated int64 // Number of generated addresses
)

const batchSize = 100000 // Increased batch size for better performance

var base32Lower = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// generateBatch generates a batch of keys and checks them against the regular expressions
func generateBatch(wg *sync.WaitGroup, regexps []*regexp.Regexp, resultChan chan<- string) {
	// Initialize fast random generator
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Preallocate buffers
	seeds := make([]byte, batchSize*ed25519.SeedSize)
	publicKeys := make([][32]byte, batchSize)
	privateKeys := make([][64]byte, batchSize)
	var tmp [48]byte
	var addressBytes [35]byte

	for {
		// Generate random seeds
		rnd.Read(seeds)

		// Generate keys
		for i := 0; i < batchSize; i++ {
			seed := seeds[i*ed25519.SeedSize : (i+1)*ed25519.SeedSize]
			privateKey := ed25519.NewKeyFromSeed(seed)
			copy(privateKeys[i][:], privateKey)
			copy(publicKeys[i][:], privateKey[32:])
		}
		atomic.AddInt64(&generated, int64(batchSize))

		// Check generated keys
		for i := 0; i < batchSize; i++ {
			onionAddress := encodePublicKey(publicKeys[i][:], &tmp, &addressBytes)
			for _, re := range regexps {
				if re.MatchString(onionAddress) {
					resultChan <- onionAddress
					save(onionAddress, publicKeys[i][:], expandSecretKey(privateKeys[i][:]))
					atomic.AddInt64(&found, 1)
					wg.Done()
					break
				}
			}
		}
	}
}

// expandSecretKey expands the secret key to 64 bytes
func expandSecretKey(secretKey []byte) [64]byte {
	var hashInput [32]byte
	copy(hashInput[:], secretKey[:32])
	hash := sha3.Sum512(hashInput[:])
	hash[0] &= 248
	hash[31] &= 127
	hash[31] |= 64
	return hash
}

// encodePublicKey encodes the public key into an onion address
func encodePublicKey(publicKey []byte, tmp *[48]byte, addressBytes *[35]byte) string {
	copy(tmp[0:], ".onion checksum")
	copy(tmp[15:], publicKey)
	tmp[47] = 0x03
	checksum := sha3.Sum256(tmp[:])

	copy(addressBytes[0:], publicKey)
	copy(addressBytes[32:], checksum[:2])
	addressBytes[34] = 0x03

	return base32Lower.EncodeToString(addressBytes[:])
}

// save stores the generated keys and address in files
func save(onionAddress string, publicKey []byte, secretKey [64]byte) {
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
		go generateBatch(&wg, regexps, resultChan)
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
