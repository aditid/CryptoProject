// Encrypt or decrypt/verify the file under AES_GCM
// April 6, 2017
// Sarah Scheffler

var sodium = require('sodium').api;

// Generate keys for AES_GCM
// TODO: why allocUNsafe???
var key = Buffer.allocUnsafe(sodium.crypto_aead_aes256gcm_KEYBYTES);
sodium.randombytes_buf(key);

//TODO: should we be using SIV?  We COULD also try OCB, just saying.
// Generate random nonce
var nonce = Buffer.allocUnsafe(sodium.crypto_aead_aes256gcm_NPUBBYTES);
sodium.randombytes_buf(nonce);

var state = sodium.crypto_aead_aes256gcm_beforenm(key);
var message = Buffer.from("this is a message yessiree"); //TODO: read from file
var additionalData = Buffer.from("metadatametadata");

// Encryption step
var ciphertext = sodium.crypto_aead_aes256gcm_encrypt_afternm(
        message, additionalData, nonce, state);

console.log("hi there:");
console.log(ciphertext);
console.log("done now");

var plaintext = sodium.crypto_aead_aes256gcm_decrypt_afternm(
        ciphertext, additionalData, nonce, state);

console.log("and again:");
console.log(plaintext.toString('ascii', 0, plaintext.length));
console.log("really done");

//TODO: AES_GCM only supported for HW-accelerated.  If this
//is a problem, try ChaCha20-Poly1305

