const fs = require('fs');
const http = require('http');
const openpgp = require('openpgp');
const process = require('process');
const readline = require('readline');

let config;

let data = {
	request: {
		method: 'sendMessage',
		to: 'Alice',
		message: 'Hello!'
		}
};

let jsonData = JSON.stringify(data);

process.stdout.write('\x1Bc');

hasJsonStructure = function hasJsonStructure(str) {
    if (typeof str !== 'string') return false;
    try {
        const result = JSON.parse(str);
        const type = Object.prototype.toString.call(result);
        return type === '[object Object]' 
            || type === '[object Array]';
    } catch (err) {
        return false;
    }
}

try {
	console.log('Checking "config.json" file...');
	let contents = fs.readFileSync(__dirname + '/config.json');
	if (hasJsonStructure(contents.toString()) === true) {
		config = JSON.parse(contents);
		console.log('\x1b[1m%s\x1b[0m', '"config.json" has been read ✔️');
//		console.log(config);
		console.log();
	} else {
		process.exit(1);
	}
} catch (err) {
	console.error(`Could not read config.json file: ${err}`);
	process.exit(1);
}


(async () => {
    // put keys in backtick (``) to avoid errors caused by spaces or tabs
    const publicKeyArmored = config['publicKey'];
    const privateKeyArmored = config['privateKey'];
    const passphrase = config['passphrase']; // what the private key is encrypted with

    const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });

    const privateKey = await openpgp.decryptKey({
        privateKey: await openpgp.readPrivateKey({ armoredKey: privateKeyArmored }),
        passphrase
    });

    const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ text: 'Hello, World!' }), // input as Message object
        encryptionKeys: publicKey,
        signingKeys: privateKey // optional
    });
    console.log(encrypted); // '-----BEGIN PGP MESSAGE ... END PGP MESSAGE-----'

    const message = await openpgp.readMessage({
        armoredMessage: encrypted // parse armored message
    });
    const { data: decrypted, signatures } = await openpgp.decrypt({
        message,
        verificationKeys: publicKey, // optional
        decryptionKeys: privateKey
    });
    console.log(decrypted); // 'Hello, World!'
    // check signature validity (signed messages only)
    try {
        await signatures[0].verified; // throws on invalid signature
        console.log('Signature is valid');
    } catch (e) {
        throw new Error('Signature could not be verified: ' + e.message);
    }
})();
