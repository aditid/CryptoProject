// Do entire login process, start from a known salt/hash, Pubk, and Enc_KEK(Privk)
// April 22, 2017 // Happy Earth Day!
// Sarah Scheffler

///////////////////////////////////////////////////////////////////////////////
// IMPORTS
///////////////////////////////////////////////////////////////////////////////

// Imports
var sodium = require('sodium').api;
var assert = require('assert');

///////////////////////////////////////////////////////////////////////////////
// CONSTANTS
///////////////////////////////////////////////////////////////////////////////

var SYMKEY_LEN = sodium.crypto_aead_aes256gcm_KEYBYTES;
var PUBKEY_LEN = sodium.crypto_box_PUBLICKEYBYTES;
var PRIVKEY_LEN = sodium.crypto_box_SECRETKEYBYTES;
var SALT_LEN = sodium.crypto_pwhash_argon2i_SALTBYTES;
var SYM_NONCE_LEN = sodium.crypto_aead_aes256gcm_NPUBBYTES;
var PUB_NONCE_LEN = sodium.crypto_box_NONCEBYTES;
var OPS_LIMIT = sodium.crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE; //TODO check this
var MEM_LIMIT = sodium.crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE; //TODO check this
var KDF_ALGORITHM = sodium.crypto_pwhash_argon2i_ALG_ARGON2I13;
var DELIMITER = "|";
//TODO: argon2 vs scrypt
// as far as I can tell, argon2 is more configurable and also newer (?)

///////////////////////////////////////////////////////////////////////////////
// HELPER FUNCTIONS
///////////////////////////////////////////////////////////////////////////////

/**
 * Creates and returns a random buffer of the specified length
 * @param {int} length
 * @return {Buffer} random buffer of this length
 */
function randomBuffer(length) {
    var buffer = Buffer.allocUnsafe(length);
    sodium.randombytes_buf(buffer);
    return buffer;
}

///////////////////////////////////////////////////////////////////////////////
// KEYS AND KNOWN VALUES
///////////////////////////////////////////////////////////////////////////////

var userPubPrivKeys = sodium.crypto_box_keypair(); // user's keypair
var Pubu = userPubPrivKeys.publicKey; // user's public key (stored)
var Privu = userPubPrivKeys.secretKey; // user's private key (enc under KEK)
var salt = randomBuffer(SALT_LEN); // stored with PW hash
var password = "userpw123" // user1's password

///////////////////////////////////////////////////////////////////////////////
// Record encryption process
///////////////////////////////////////////////////////////////////////////////

// At this point, we have
var privKeyShareServer = randomBuffer(PRIVKEY_LEN);
var privKeyShareUser = Buffer.allocUnsafe(PRIVKEY_LEN);
for (var i=0; i < PRIVKEY_LEN; ++i) {
    privKeyShareUser[i] = Privu[i] ^ privKeyShareServer[i];
}
var pubKeyUser = Pubu;
var adminKeys = sodium.crypto_box_keypair();

// New record
var record = Buffer.from("i am a record");
// Generate record key
var recordKey = randomBuffer(SYMKEY_LEN);
// Encrypt record under record key
var nonce1 = randomBuffer(SYM_NONCE_LEN);
var recordCiphertext = sodium.crypto_aead_aes256gcm_encrypt(record,
        Buffer.from(""), nonce1, recordKey);

// Encrypt record key under user's public key
var nonce2 = randomBuffer(PUB_NONCE_LEN);
var recordKeyCiphertext = sodium.crypto_box(recordKey, nonce2, pubKeyUser,
        adminKeys.secretKey);
if (!recordKeyCiphertext) {
    throw("error");
}

// Decrypt record key using user's private key
var privKeyUser = Buffer.allocUnsafe(PRIVKEY_LEN);
for (var i=0; i < PRIVKEY_LEN; ++i) {
    privKeyUser[i] = privKeyShareServer[i] ^ privKeyShareUser[i];
}
recordKey = sodium.crypto_box_open(recordKeyCiphertext, nonce2, adminKeys.publicKey,
        privKeyUser);
if (!recordKey) {
    throw("error");
}

// Decrypt record using record key
record = sodium.crypto_aead_aes256gcm_decrypt(recordCiphertext, Buffer.from(""),
        nonce1, recordKey);




