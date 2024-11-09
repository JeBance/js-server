//const openpgp = require('openpgp');
const process = require('process');
const securePGPstorage = require('./index.js');

process.stdout.write('\x1Bc');
console.log('\x1b[1m%s\x1b[0m', 'Starting testing...\n');

sPGPs = new securePGPstorage();

(async () => {

	console.log('\x1b[1m%s\x1b[0m', '1. Create storage');
	console.log('////////////////////////////////////////////////////////////');
	await sPGPs.createStorage('John Smith', 'john.smith@gmail.com', '1q2w3e4r5t6y7u8i9o0p');
	console.log('Nickname:', sPGPs.nickname);
	console.log('E-mail:', sPGPs.email);
	console.log('Fingerprint:', sPGPs.fingerprint);
	console.log('Public key:');
	console.log(sPGPs.publicKeyArmored);
	console.log('////////////////////////////////////////////////////////////\n\n\n');



	console.log('\x1b[1m%s\x1b[0m', '2. Checking the activity of all data in the storage');
	console.log('////////////////////////////////////////////////////////////');
	console.log('All data is activated:', await sPGPs.checkAllData());
	console.log('////////////////////////////////////////////////////////////\n\n\n');



	console.log('\x1b[1m%s\x1b[0m', '3. Encrypt String data with PGP keys');
	console.log('////////////////////////////////////////////////////////////');
	const recipientPublicKeyArmored = sPGPs.publicKeyArmored;
	let encrypted = await sPGPs.encryptMessage('Hello world!', recipientPublicKeyArmored, true);
	console.log('Encrypted message:');
	console.log(encrypted);
	console.log('Check message:', await sPGPs.checkMessage(encrypted));
	console.log('////////////////////////////////////////////////////////////\n\n\n');



	console.log('\x1b[1m%s\x1b[0m', '4. Decrypt String data with PGP keys');
	console.log('////////////////////////////////////////////////////////////');
	const senderPublicKeyArmored = sPGPs.publicKeyArmored;
	let decrypted = await sPGPs.decryptMessage(encrypted, senderPublicKeyArmored);
	console.log('Decrypted message:');
	console.log(decrypted);
	console.log(decrypted.data);
	console.log(decrypted.signatures[0].keyID.toHex());
	console.log(sPGPs.fingerprint);
	await decrypted.signatures[0].verified;
	console.log('////////////////////////////////////////////////////////////\n\n\n');



	console.log('\x1b[1m%s\x1b[0m', '5. Encrypt symmetrically with compression');
	console.log('////////////////////////////////////////////////////////////');
	encrypted = await sPGPs.encryptMessageSymmetricallyWithCompression('Hello again!', '1234567890');
	console.log('Encrypted message:');
	console.log(encrypted);
	console.log('Check message:', await sPGPs.checkMessage(encrypted));
	console.log('////////////////////////////////////////////////////////////\n\n\n');



	console.log('\x1b[1m%s\x1b[0m', '6. Decrypt symmetrically with compression');
	console.log('////////////////////////////////////////////////////////////');
	decrypted = await sPGPs.decryptMessageSymmetricallyWithCompression(encrypted, '1234567890');
	console.log('Decrypted message:');
	console.log(decrypted);
	console.log('////////////////////////////////////////////////////////////\n\n\n');



	console.log('\x1b[1m%s\x1b[0m', '7. Storage encryption');
	console.log('////////////////////////////////////////////////////////////');
	const encryptedStorage = await sPGPs.encryptStorage();
	console.log('Encrypted storage:');
	console.log(encryptedStorage);
	console.log('Check message:', await sPGPs.checkMessage(encryptedStorage));
	console.log('encodeURIComponent (for file href html):', await sPGPs.generateSecureFile());	
	console.log('////////////////////////////////////////////////////////////\n\n\n');



	console.log('\x1b[1m%s\x1b[0m', '8. Clearing data from storage');
	console.log('////////////////////////////////////////////////////////////');
	await sPGPs.eraseAllData();
	console.log('Nickname:', sPGPs.nickname);
	console.log('E-mail:', sPGPs.email);
	console.log('Fingerprint:', sPGPs.fingerprint);
	console.log('Public key:');
	console.log(sPGPs.publicKeyArmored);
	console.log('All data is activated:', await sPGPs.checkAllData());
	console.log('////////////////////////////////////////////////////////////\n\n\n');



	console.log('\x1b[1m%s\x1b[0m', '9. Storage decryption');
	console.log('////////////////////////////////////////////////////////////');
	const decryptedStorage = await sPGPs.decryptStorage(encryptedStorage, '1q2w3e4r5t6y7u8i9o0p');
	console.log('Decrypted storage:', decryptedStorage);
	console.log('Nickname:', sPGPs.nickname);
	console.log('E-mail:', sPGPs.email);
	console.log('Fingerprint:', sPGPs.fingerprint);
	console.log('Public key:');
	console.log(sPGPs.publicKeyArmored);
	console.log('All data is activated:', await sPGPs.checkAllData());
	console.log('////////////////////////////////////////////////////////////\n\n\n');

})();

