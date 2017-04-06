// Encrypt or decrypt/verify the file under AES_GCM
// April 6, 2017
// Sarah Scheffler

var sodium = require('sodium').api;
var assert = require('assert');

// Generate keys for AES_GCM
// TODO: why allocUNsafe???
var key = Buffer.allocUnsafe(sodium.crypto_aead_aes256gcm_KEYBYTES);
sodium.randombytes_buf(key);

//TODO: should we be using SIV?  We COULD also try OCB, just saying.
//TODO: what's the difference between NPUBBYTES and NONCEBYTES?:w
// Generate random nonce
var nonce = Buffer.allocUnsafe(sodium.crypto_aead_aes256gcm_NPUBBYTES);
sodium.randombytes_buf(nonce);

//TODO: There's an extended API that splits up incorporating the
//key and the actual encryption steps.  If we're encrypting
//a lot of things under the same key, it might be worth doing.

var message = Buffer.from("this is a message yessiree"); //TODO: read from file
var additionalData = Buffer.from("metadatametadata");
var additionalDataFAKE = Buffer.from("this is different metadata");

// Encrypt
var ciphertext = sodium.crypto_aead_aes256gcm_encrypt(
        message, additionalData, nonce, key)

// Decrypt
var plaintext = sodium.crypto_aead_aes256gcm_decrypt(
        ciphertext, additionalData, nonce, key);
var plaintextFAKE = sodium.crypto_aead_aes256gcm_decrypt(
        ciphertext, additionalDataFAKE, nonce, key);

console.log("Encryption of message (in buffer form) is:");
console.log(ciphertext);

console.log("Correct decryption (in string form) is:");
assert.notEqual(typeof plaintext, 'undefined');
console.log(plaintext.toString());
console.log("And the plaintext is an ", typeof plaintext);

console.log("If decryption isn't auth, type of decrypted text is 'undefined', as shown here.")
assert.equal(typeof plaintextFAKE, 'undefined');
console.log("Type of plaintextfake: ", typeof plaintextFAKE);
console.log("Yes, apparently the actual way to demonstrate this is to check the type of plaintext and see if it's undefined.");

//TODO: AES_GCM only supported for HW-accelerated.  If this
//is a problem, try ChaCha20-Poly1305

