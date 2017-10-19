package main

import(
	"fmt"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"os"
	"encoding/binary"
)

// encryptFile encrypts a filename. The format of the output file is:
// * Random nonce used for encryption, standard size given by GCM
// * The buffer size used, as an unsigned 32 int, little endian
// * Ciphertext:
// 		* Length of the following chunk ciphertext, as an unsigned 32 int, little endian
//		* The actual ciphertext
func encryptFile(filename string, outfilename string, key []byte, buffer_size uint32) error {
	// The AES cipher
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	
	// GCM mode wrapper.
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return err
	}
	
	// Generate a random nonce, of wathever nonce size the standard
	// library decides it's standard
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return err
	}
	
	// The plaintext file
	fplain, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer fplain.Close()
	
	// The ciphertext file
	fcipher, err := os.Create(outfilename)
	if err != nil {
		return err
	}
	defer fcipher.Close()
	
	// Starting of the interesting part. First thing we write to our
	// homegrown file format is our nonce
	_, err = fcipher.Write(nonce)
	if err != nil {
		return fmt.Errorf("writing nonce: %v", err)
	}
	
	// Make a buffer
	buff := make([]byte, buffer_size)
	
	// For decryption, we need to know how big our chunks were when
	// encrypting. See decryption to know why
	err = binary.Write(fcipher, binary.LittleEndian, buffer_size)
	if err != nil {
		return fmt.Errorf("writing buffer size: %v", err)
	}
	
	// Main ciphertext writing loop
	for {
		n, err := fplain.Read(buff)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return err
			}
		}
		
		ciphertext := gcm.Seal(nil, nonce, buff[:n], nil)
		
		// Before the actual ciphertext, we write how long it was.
		err = binary.Write(fcipher, binary.LittleEndian, uint32(len(ciphertext)))
		if err != nil {
			return fmt.Errorf("writing ciphertext length: %v", err)
		}
		
		// Write the actual ciphertext
		_, err = fcipher.Write(ciphertext)
		if err != nil {
			return err
		}
	}
	
	// All fine
	return nil
}

// decryptFile decrypts a file made by encryptFile, in the same format.
func decryptFile(filename string, outfilename string, key []byte) error {
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return err
	}
	
	fcipher, err := os.Open(filename)
	if err != nil {
		return err
	}
	
	// Read nonce. Length will be the standard.
	nonce := make([]byte, gcm.NonceSize())
	_, err = fcipher.Read(nonce)
	if err != nil {
		return fmt.Errorf("reading nonce: %v", err)
	}
	
	// We generate a buffer at least as long as the one originally
	// used, *plus* what GCM specifies as it's overhead. That
	// way, we assure we will have enough space for an entire
	// chunk
	var buffer_size uint32
	err = binary.Read(fcipher, binary.LittleEndian, &buffer_size)
	if err != nil {
		return fmt.Errorf("reading buffer size: %v", err)
	}
	buff := make([]byte, int(buffer_size) + gcm.Overhead())
	
	fplain, err := os.Create(outfilename)
	if err != nil {
		return nil
	}
	
	var current_len uint32
	
	// Process the (len, ciphertext) pairs
	for {
		// First thing first, we read the length of the following ciphertext chunk
		err = binary.Read(fcipher, binary.LittleEndian, &current_len)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return fmt.Errorf("reading a ciphertext length: %v", err)
			}
		}
		
		// We generate a slice based off the main buffer, but of the exact
		// length we need (which we've assured will be <= len(buff)), ready
		// to pass to a Read function
		current_buff := buff[:int(current_len)]
		
		// Read the ciphetext. If we've made everything well, we will have
		// exactly one whole chunk, no more, no less
		_, err = fcipher.Read(current_buff)
		if err != nil {
			return err // This should *not* be io.EOF. Supposedly, we've already dealt with it
		}
		
		// Decrypt and write plaintext to file
		
		plaintext, err := gcm.Open(nil, nonce, current_buff, nil)
		if err != nil {
			return err
		}
		
		_, err = fplain.Write(plaintext)
		if err != nil {
			return fmt.Errorf("writing plaintext: %v", err)
		}
	}
	
	return nil
}
