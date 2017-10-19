package main

import(
	"fmt"
	"flag"
	"crypto/sha256"
	"path/filepath"
	"os"
	"strings"
)

const(
	DEFAULT_BUFFER_SIZE uint32 = 4096 * 16
	DEFAULT_KEY_ITERATIONS int = 10000
)

func main() {
	// Flags config
	var buffer_size = flag.Int("b", int(DEFAULT_BUFFER_SIZE), "default `buffer size` to use in encryption")
	var decryption_mode = flag.Bool("d", false, "engage decryption mode")
	var password = flag.String("p", "", "`password` to use. Yes, asking for a password on the command line is probably bad. Don't do it in real stuff")
	
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "use: %s [-b buffer_size] [-p password] [-d] FILE\n", filepath.Base(os.Args[0]) )
		flag.PrintDefaults()
	}
	
	flag.Parse()
	
	// Main logic
	
	if len(flag.Args()) < 1 { // There was no filename passed
		fmt.Fprintf(os.Stderr, "please pass a filename\n")
		flag.Usage()
		os.Exit(2)
	}
	
	if *password == "" {
		fmt.Printf("Enter password: ")
		fmt.Scanln(password)
	}
	
	// A probably horrible key generation
	
	shaer := sha256.New()
	
	shaer.Write([]byte(*password))
	
	for i := 0; i < DEFAULT_KEY_ITERATIONS - 1; i++ {
		shaer.Write(shaer.Sum(nil))
	}
	
	// Actual encryption key. You need exactly 32 bytes for AES-256
	key := shaer.Sum(nil)[:32]
	
	if !*decryption_mode { // encryption
		encryptFile(flag.Arg(0), flag.Arg(0) + ".aes", key, uint32(*buffer_size))
	} else {
		var outfilename string
		
		if strings.HasSuffix(flag.Arg(0), ".aes") {
			outfilename = strings.TrimSuffix(flag.Arg(0), ".aes")
		} else {
			fmt.Printf("Input output file: ")
			fmt.Scanln(&outfilename)
		}
		
		decryptFile(flag.Arg(0), outfilename, key)
	}
}
