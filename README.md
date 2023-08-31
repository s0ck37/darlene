# DARLENE
A basic AES-256 cryptographic program for GNU/Linux systems.
## Warning
Darlene is in development phase for now, so no good criptographic practices are ensured.  
For the moment Darlene adds a cero padding so the hash from the decrypted file may differ from the original one.
## Building
For building Darlene from source:
```
$ git clone https://github.com/s0ck37/darlene
$ cd darlene
$ bash compile.sh
```
The compiled binary will be placed in the **build/** directory.
## Future plans
- Add encryption by blocks to support larger files.
## Bugs or requests
Feel free to create a **pull request** or **issue**, everything will be read and taken into account.
## License
This program is licensed under GNU GPL 3.0
