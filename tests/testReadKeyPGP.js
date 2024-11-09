const process = require('process');
process.stdout.write('\x1Bc');

const securePGPstorage = require('secure-pgp-storage');
const letsconfig = require('letsconfig');

const config = new letsconfig({}, __dirname + '/../');
const sPGPs = new securePGPstorage();




(async () => {
	await sPGPs.decryptStorage(config.secureKey, config.passphrase);
	let key = await sPGPs.readKey(sPGPs.publicKeyArmored);
	console.log(key);
	console.log(key.getFingerprint());
	console.log(key.getKeyID().toHex());
})();

