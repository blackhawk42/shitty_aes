# shitty_aes
A toy program in Go to encrypt a file with AES-GCM.

# Raison d'être

In my journey to understand the cryptographic capabilities of Golang, I couldn't find and example of whole-file encryption with AES in GCM mode. Everyone either used CFB, the same semi-copypasted example of encrypting a single string, or had the horrible assumption that the whole file could be read into memory.

So I made my own. It reads the file in chunks, so you can work with GB of size.

This is probably not the most efficient, clear or beautiful code but, if by any chance you arrived here looking for the same answers I couldn't find, this is better than nothing, I guess.

If you want to contribute, even if just with comments, that would be awesome. Just keep in mind the limited, mostly educational scope of this little thing.

# DISCLAIMER
The explicit purpose of this program was to practice with the standard Go library, without no extras or future planning. Therefore, common sense things like using a real key generation function, turning off terminal echo when readding passwords or a sensible file format are not here.

YOU SHOULDN'T USE THIS FOR REAL, ACTUAL SECURITY. **NO**. That's what GPG is for. Hell, that's what WinRAR's "password" field is for.

The main value of this thing is in the way individual chunks are read, encrypted and decrypted with Go's crypto/cipher library, and even that is probably sloppilly implemented.

You have been warned.
