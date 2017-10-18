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
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return err
	}
	
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return err
	}
	
	fplain, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer fplain.Close()
	
	fcipher, err := os.Create(outfilename)
	if err != nil {
		return err
	}
	defer fcipher.Close()
	
	_, err = fcipher.Write(nonce)
	if err != nil {
		return fmt.Errorf("writing nonce: %v", err)
	}
	
	buff := make([]byte, buffer_size)
	
	err = binary.Write(fcipher, binary.LittleEndian, buffer_size)
	if err != nil {
		return fmt.Errorf("writing buffer size: %v", err)
	}
	
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
		
		err = binary.Write(fcipher, binary.LittleEndian, uint32(len(ciphertext)))
		if err != nil {
			return fmt.Errorf("writing ciphertext length: %v", err)
		}
	
		_, err = fcipher.Write(ciphertext)
		if err != nil {
			return err
		}
	}
	
	// All fine
	return nil
}

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
	
	nonce := make([]byte, gcm.NonceSize())
	_, err = fcipher.Read(nonce)
	if err != nil {
		return fmt.Errorf("reading nonce: %v", err)
	}
	
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
	
	for {
		err = binary.Read(fcipher, binary.LittleEndian, &current_len)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return fmt.Errorf("reading a ciphertext length: %v", err)
			}
		}
		
		current_buff := buff[:int(current_len)]
		
		_, err = fcipher.Read(current_buff)
		if err != nil {
			return err // This should *not* be io.EOF. Supposedly, we've already dealt with it
		}
		
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
