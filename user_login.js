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

var KEY_LEN = sodium.crypto_aead_aes256gcm_KEYBYTES;
var SALT_LEN = sodium.crypto_pwhash_argon2i_SALTBYTES;
var NONCE_LEN = sodium.crypto_aead_aes256gcm_NPUBBYTES;
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
// DEFINITIONS AND ASSUMPTIONS
///////////////////////////////////////////////////////////////////////////////
//
// Pubu, Privu = the user's public and private keys
// KEK = the symmetric key derived by the user's password that unlocks their private key
// Rs = the server component of Privu
// Ru = the user component of Privu
//      (Rs xor Ru = Privu)
// salt = the user's salt
// hash = the user's hash
//
// Assuming all files have a unique fileID
// Assuming all keys already generated
//

///////////////////////////////////////////////////////////////////////////////
// KEYS AND KNOWN VALUES
///////////////////////////////////////////////////////////////////////////////

var userPubPrivKeys = sodium.crypto_box_keypair(); // user's keypair
var Pubu = userPubPrivKeys.publicKey; // user's public key (stored)
var Privu = userPubPrivKeys.secretKey; // user's private key (enc under KEK)
var salt = randomBuffer(SALT_LENGTH); // stored with PW hash
var password = "userpw123" // user1's password

///////////////////////////////////////////////////////////////////////////////
// LOGIN PROCESS
///////////////////////////////////////////////////////////////////////////////

// 1. User sends username + password to server

// 2. Server uses argon2 to generate hash for auth and kek



///////////////////////////////////////////////////////////////////////////////
// GENERATION OF USER KEYS
///////////////////////////////////////////////////////////////////////////////

/**
 * Generates user key using Argon2i
 * @param {Buffer} password
 * @param {Buffer} salt
 * @return {Buffer} Ku, the user's half of their symmetric key
 */
function generateKu(password, salt) {
    var Ku = Buffer.allocUnsafe(KEY_LEN);
    sodium.crypto_pwhash_argon2i(Ku, password, salt,
            OPS_LIMIT, MEM_LIMIT, KDF_ALGORITHM);
    return Ku; //TODO: does this need to be passed into the function?
}

/**
 * Generates a random number which is XORed with Ku to get Ksu.  This MUST
 * be saved somewhere or else the key will no longer function.
 * @return {Buffer} Ks, the server's half of the user's symmetric key
 */
function generateKs() {
    return randomBuffer(KEY_LEN);
}

/**
 * XORs Ku and Ks to get Ksu
 * @param {Buffer} Ku, the user's half of their key
 * @param {Buffer} Ks, the server's half of this user key
 * @return {Buffer} Ksu, the XOR of Ku and Ks, and the symmetric encryption
 *                       key for this user
 */
function generateKsu(Ku, Ks) {
    assert(Ku.length == Ks.length && Ks.length == KEY_LEN);
    var Ksu = Buffer.allocUnsafe(KEY_LEN);
    for (var i=0; i < KEY_LEN; ++i) {
        Ksu[i] = Ku[i] ^ Ks[i];
    }
    return Ksu
}

var salt = randomBuffer(SALT_LEN);
var password = Buffer.from("a user typed this");

var Ku = generateKu(password, salt);
var Ks = generateKs();
var Ksu = generateKsu(Ku, Ks);

console.log("Ku (never store):", Ku);
console.log("Salt (store server-side):", salt);
console.log("Ks (store server-side):", Ks);
console.log("Ksu (never store):", Ksu);


//TODO: sanitize all inputs

///////////////////////////////////////////////////////////////////////////////
// USER KEYS AND FILE INFO
///////////////////////////////////////////////////////////////////////////////

/**
 * @return {Buffer} return a 256-bit AES key
 */
function generateFileKey() {
    return randomBuffer(KEY_LEN);
}

// File ID and file key
var fileID = 1;
var file = Buffer.from("This is a file buffer");
var fileKey = generateFileKey();

// Users and their keys
//TODO: for now, users are strings. They should be some kind of uniqueID.
//TODO: this should be GCM_SIV, not plain GCM.

// TBH I'm not really sure how we should manage this but I'm leaving it here in case it's helpful
var userKeys = {};
var patient1 = "abcd efg"
var patient1Key = Buffer.allocUnsafe(sodium.crypto_aead_aes256gcm_KEYBYTES);
sodium.randombytes_buf(patient1Key);
userKeys[patient1] = patient1Key;
var doctor1 = "hijkl mnopqr"
var doctor1Key = Buffer.allocUnsafe(sodium.crypto_aead_aes256gcm_KEYBYTES);
sodium.randombytes_buf(doctor1Key);
userKeys[doctor1] = doctor1Key;

///////////////////////////////////////////////////////////////////////////////
// ENCRYPTION
///////////////////////////////////////////////////////////////////////////////

/**
 * @param fileID - the unique identifier of the file
 * @param users - list of users who have access to this file
 * @param userkeys - list of encrypted file keys (same order as users)
 * @param nonces - list of nonces for file key decryption
 * @return {Buffer} encoded metadata information about this file - which
 *         users can access this and the encrypted file keys - format is:
 *         |FILE_ID|NUM_USERS|USER1|...|USERN|KEY1|...|KEYN|NONCE1|...|NONCEN|
 *         where '|' is DELIMITER.  Note the trailing |
 */
function encodeMetadata(fileID, users, encryptedFileKeys, nonces) {
    //TODO: for now, users and userkeys are assumed to be lists of equal
    //length with the same ordering
    var metadata = DELIMITER + fileID + DELIMITER + users.length + DELIMITER;
    assert(users.length == encryptedFileKeys.length);
    assert(users.length == nonces.length);
    for (var i=0; i < users.length; ++i) {
        metadata += users[i] + DELIMITER;
    }
    for (var i=0; i < encryptedFileKeys.length; ++i) {
        metadata += encryptedFileKeys[i] + DELIMITER;
    }
    for (var i=0; i < nonces.length; ++i) {
        metadata += nonces[i] + DELIMITER;
    }
    return metadata;
}

/**
 * @param fileMetadata {Buffer} metadata formatted as:
 *         |FILE_ID|NUM_USERS|USER1|...|USERN|KEY1|...|KEYN|NONCE1|...|NONCEN|
 *         where '|' is DELIMITER.  Note the trailing |
 * @return [fileID, users, encryptedFileKeys, nonces] where fileID is an int,
 *         users, encryptedFileKeys, and nonces are all Buffers
 */
function decodeMetadata(fileMetadata) {
    var splitMetadata = fileMetadata.toString().split(DELIMITER);
    var fileID = splitMetadata[0].parseInt();
    var numUsers = splitMetadata[1].parseInt();
    var users = [];
    var encryptedFileKeys = [];
    var nonces = [];
    for (var i=0; i < numUsers; ++i) {
        users.push(splitMetadata[2 + i]);
        encryptedFileKeys.push(splitMetadata[2 + numUsers + i]);
        nonces.push(splitMetadata[2 + 2*numUsers + i]);
    }
    return [fileID, users, encryptedFileKeys, nonces];
}

/**
 * Encrypt the file key under the Ksu, return [nonce, encFileKey]
 * @param {Buffer} Ksu - The user's full symmetric key
 * @param {Buffer} fileKey - the key to be encrypted
 * @return [nonce, ciphertext] where the decryption is 
 *         decrypt(ciphertext, Buffer.from(""), nonce, Ksu)
 *         Both nonce and ciphertext are Buffers.
 */
function encryptFileKeyUnderKsu(Ksu, fileKey) {
    var nonce = randomBuffer(NONCE_LEN);
    var ciphertext = sodium.crypto_aead_aes256gcm_encrypt(fileKey, 
            Buffer.from(""), nonce, Ksu);
    return [nonce, ciphertext]
}

/*
 * Encrypt the file under the file key, return [nonce, encFile],
 * note that you have to hold on to the file metadata
 * @param {Buffer} fileKey - the file key to encrypt this file
 * @param {Buffer} file - the file to be encrypted
 * @param {Buffer} fileMetadata - the metadata for this file;
 *                 is required for decryption
 * @return [nonce, ciphertext] where the decryption is
 *         decrypt(ciphertext, fileMetadata, nonce, fileKey)
 *         Both nonce and ciphertext are Buffers.
 */
function encryptFileUnderFileKey(fileKey, file, fileMetadata) {
    var nonce = randomBuffer(NONCE_LEN);
    var ciphertext = sodium.crypto_aead_aes256gcm_encrypt(Ksu,
            fileMetadata, nonce, fileKey);
    return [nonce, ciphertext]
}

var fileID = 1;
var file = Buffer.from("hello I am a file");

var fileKey = generateFileKey();
var nonceAndCiphertext = encryptFileKeyUnderKsu(Ksu, fileKey);
var fileKeyNonce = nonceAndCiphertext[0];
var encryptedFileKey = nonceAndCiphertext[1];
var fileMetadata = encodeMetadata(fileID, [patient1], 
        [encryptedFileKey], [fileKeyNonce]);

var fileNonceAndCiphertext = encryptFileUnderFileKey(fileKey, file, fileMetadata);
var fileNonce = fileNonceAndCiphertext[0];
var encryptedFile = fileNonceAndCiphertext[1];

//TODO: There's an extended API that splits up incorporating the
//key and the actual encryption steps.  If we're encrypting
//a lot of things under the same key, it might be worth doing.

///////////////////////////////////////////////////////////////////////////////
// DECRYPTION
///////////////////////////////////////////////////////////////////////////////

// Get file key from metadata
// TODO: realistically, you'd get the encrypted file key from the file metadata,
// not from some dictionary. Though then we still have to store the nonce there?

var patient1FileKey = sodium.crypto_aead_aes256gcm_decrypt(
	encryptedFileKeys[fileID][patient1], fileKeyPatient1Metadata, nonce1, patient1Key);
var filePlaintext = sodium.crypto_aead_aes256gcm_decrypt(
	fileCiphertext, fileMetadata, nonce, patient1FileKey);

if (typeof filePlaintext == 'undefined') {
	console.log("Decryption failed");
} else {
	console.log("Decryption succeeded!");
	console.log(filePlaintext.toString());
}


