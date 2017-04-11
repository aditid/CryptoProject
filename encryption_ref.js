// Encrypt or decrypt/verify the file under AES_GCM
// April 6, 2017
// Sarah Scheffler

///////////////////////////////////////////////////////////////////////////////
// IMPORTS
///////////////////////////////////////////////////////////////////////////////

// Imports
var sodium = require('sodium').api;
var assert = require('assert');

///////////////////////////////////////////////////////////////////////////////
// USER KEYS AND FILE INFO
///////////////////////////////////////////////////////////////////////////////

// File ID and file key
var fileID = 1;
var file = Buffer.from("This is a file buffer");
var fileKey = Buffer.allocUnsafe(sodium.crypto_aead_aes256gcm_KEYBYTES);
sodium.randombytes_buf(fileKey);

// Users and their keys
//TODO: for now, users are strings. They should be some kind of uniqueID.
//TODO: this should be GCM_SIV, not plain GCM.
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

// Encrypt file key under user keys
var encryptedFileKeys = {};
var fileKeyPatient1Metadata = Buffer.from(patient1 + "|" + fileID);
var nonce1 = Buffer.allocUnsafe(sodium.crypto_aead_aes256gcm_NPUBBYTES);
encryptedFileKeys[fileID] = {};
encryptedFileKeys[fileID][patient1] = sodium.crypto_aead_aes256gcm_encrypt(fileKey,
	fileKeyPatient1Metadata, nonce1, userKeys[patient1]);
var fileKeyDoctor1Metadata = Buffer.from(doctor1 + "|" + fileID);
var nonce2 = Buffer.allocUnsafe(sodium.crypto_aead_aes256gcm_NPUBBYTES);
encryptedFileKeys[fileID][doctor1] = sodium.crypto_aead_aes256gcm_encrypt(fileKey,
	fileKeyDoctor1Metadata, nonce2, userKeys[doctor1]);

// Encrypt file under file key, and include the encrypted file keys as metadata
var fileMetadata = Buffer.from(fileID+"|||||"+
	patient1+"|"+encryptedFileKeys[fileID][patient1]+"|||"+
	doctor1+"|"+encryptedFileKeys[fileID][doctor1]+"|||");
var nonce = Buffer.allocUnsafe(sodium.crypto_aead_aes256gcm_NPUBBYTES);
sodium.randombytes_buf(nonce);
var fileCiphertext = sodium.crypto_aead_aes256gcm_encrypt(file, fileMetadata,
	nonce, fileKey);

//TODO: There's an extended API that splits up incorporating the
//key and the actual encryption steps.  If we're encrypting
//a lot of things under the same key, it might be worth doing.

///////////////////////////////////////////////////////////////////////////////
// DECRYPTION
///////////////////////////////////////////////////////////////////////////////

// Get file key from metadata
// TODO: realistically, you'd get the encrypted file key from the file metadata,
// not from some dictionary. Though then we still have to store the nonce there?
patient1Key = patient1Key;
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


