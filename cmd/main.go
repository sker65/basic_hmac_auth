package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime/pprof"

	"github.com/SenseUnit/basic_hmac_auth/handler"
)

var version = "undefined"

const (
	envKeySecret = "BASIC_AUTH_HMAC_SECRET"
)

var (
	bufferSize    = flag.Int("buffer-size", 0, "initial buffer size for stream parsing")
	hexSecret     = flag.String("secret", "", "hex-encoded HMAC secret value")
	hexSecretFile = flag.String("secret-file", "", "file containing single line with hex-encoded secret")
	showVersion   = flag.Bool("version", false, "show program version and exit")
	cpuProfile    = flag.String("cpu-profile", "", "write CPU profile to file")
)

func run() int {
	var err error

	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return 0
	}

	if *hexSecret != "" && *hexSecretFile != "" {
		log.Print("Options \"-secret\" and \"-secret-file\" are mutually exclusive. Exiting...")
		return 2
	}

	hs := os.Getenv(envKeySecret)
	if *hexSecret != "" {
		hs = *hexSecret
	}
	if *hexSecretFile != "" {
		r, err := readSecretFromFile(*hexSecretFile)
		if err != nil {
			log.Printf("read of secret from file %q failed: %v", *hexSecretFile, err)
			return 1
		}
		hs = r
	}

	if hs == "" {
		log.Print(`secret is not specified! Please set "-secret" or "-secret-file"` +
			` command line options or ` + envKeySecret + ` environment variable.`)
		return 2
	}

	secret, err := hex.DecodeString(hs)
	if err != nil {
		log.Printf("unable to hex-decode secret: %v", err)
		return 3
	}

	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	err = (&handler.BasicHMACAuthHandler{
		Secret:     secret,
		BufferSize: *bufferSize,
	}).Run(os.Stdin, os.Stdout)
	if err != nil {
		log.Printf("auth handler terminated with error: %v", err)
		return 1
	}
	return 0
}

func readSecretFromFile(filename string) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", fmt.Errorf("unable to open secret file for reading: %w", err)
	}
	defer f.Close()

	rd := bufio.NewReader(f)
	buf, err := rd.ReadBytes('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("secret file reading failed: %w", err)
	}

	buf = bytes.TrimSpace(buf)
	return string(buf), nil
}

func main() {
	log.Default().SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	os.Exit(run())
}
