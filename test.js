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

let options = {
	host: 'localhost',
	port: 8000,
	path: '/',
	method: 'POST',
	headers: {
		'Content-Type': 'application/json',
		'Content-Length': jsonData.length
	}
};

process.stdout.write('\x1Bc');
const paramUsername = process.argv[2];
const paramEmail = process.argv[3];
const paramPassphrase = process.argv[4];
// when you generate keychain
// if you see:
// error:25066067:DSO support routines:dlfcn_load:could not load the shared library
// then run:
// export OPENSSL_CONF=/dev/null

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

const checkingKeychain = new Promise((resolve, reject) => {
	console.log('Checking keychain...')

	try {
		if ((config['fingerprint'] == null)
		|| (config['passphrase'] == null)
		|| (config['publicKey'] == null)
		|| (config['privateKey'] == null)) {
			console.log('\x1b[1m%s\x1b[0m', 'Missing keychain ❌');

			if ((paramUsername != null && typeof paramUsername !== "undefined")
			|| (paramEmail != null && typeof paramEmail !== "undefined")
			|| (paramPassphrase != null && typeof paramPassphrase !== "undefined")) {
				console.log('Generate keychain...');

				(async () => {
					const { privateKey, publicKey } = await openpgp.generateKey({
						type: 'rsa', // Type of the key
						rsaBits: 4096, // RSA key size (defaults to 4096 bits)
						userIDs: [{ name: paramUsername, email: paramEmail }], // you can pass multiple user IDs
						passphrase: paramPassphrase // protects the private key
					});

					pubKey = await openpgp.readKey({ armoredKey: publicKey });
					config['fingerprint'] = (pubKey.getFingerprint()).toUpperCase();
					config['passphrase'] = paramPassphrase;
					config['publicKey'] = publicKey;
					console.log('publicKey generated successfully ✔️');
					config['privateKey'] = privateKey;
					console.log('privateKey generated successfully ✔️');
					fs.writeFileSync(__dirname + '/config.json', JSON.stringify(config));
					console.log('Keychain saved successfully ✔️');
					console.log();
					resolve(true);
				})();

			} else {
				console.error('\x1b[1m%s\x1b[0m', 'Run the server with the Nickname, Email and Passphrase parameters. For example, "node server.js MyNickname MyName@somemail.com MyPassphrase".');
				process.exit(1);
			}

		} else {
			console.log('Keychain available ✔️');
			console.log();
			console.log(data.request);
			resolve(true);
		}
	} catch (err) {
		console.error('\x1b[1m%s\x1b[0m', `Failed to create keychain: ${err}`);
		process.exit(1);
	}

});

let encryptMessage = (async () => {
	data = {
		request: {
			method: 'sendMessage',
			to: 'Alice',
			message: 'Hello!'
			}
	};
	console.log();
	console.log('Encrypting message...');
	//let message = JSON.stringify(data.request.message);
	let passphrase = config['passphrase'];
	try {
		const publicKey = await openpgp.readKey({ armoredKey: config['publicKey'] });
//		console.log(publicKey);
//		console.log();
		const privateKey = await openpgp.decryptKey({
			privateKey: await openpgp.readPrivateKey({ armoredKey: config['privateKey'] }), 
			passphrase
		});
//		console.log(privateKey);
//		console.log();

		try {
			const encrypted = await openpgp.encrypt({
				message: await openpgp.createMessage({ text: data.request.message }),
				encryptionKeys: publicKey,
				signingKeys: privateKey
			});
//			console.log(encrypted);

			let nonce = new Date().getTime();
			data.request.message = encrypted;
			data.request.nonce = nonce;

//			console.log();
//			console.log(data);

			console.log();
			console.log('Signing request...');
			let signingRequest = JSON.stringify(data.request);
//			console.log();
//			console.log(signingRequest);
/*
			const unsignedMessage = await openpgp.createCleartextMessage({ text: signingRequest });
			const cleartextMessage = await openpgp.sign({
				message: unsignedMessage,
				signingKeys: privateKey
			});
//			console.log(cleartextMessage);
*/
			const message = await openpgp.createMessage({ text: signingRequest });
			const detachedSignature = await openpgp.sign({
				message, // Message object
				signingKeys: privateKey,
				detached: true
			});
//			console.log(detachedSignature);

//			data.signature = cleartextMessage;
			data.signature = detachedSignature;

			jsonData = JSON.stringify(data);
//			console.log();
//			console.log(jsonData);

			options = {
				host: 'localhost',
				port: 8000,
				path: '/',
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Content-Length': jsonData.length
				}
			};

		} catch(e) {
			console.log('Не удалось зашифровать сообщение!\n',  e);
		}
	} catch(e) {
		console.log('Не удалось прочитать публичный ключ получателя!\n',  e);
	}

});


checkingKeychain
	.then((value) => {
		let timerId = setInterval(async () => {

			await encryptMessage();

			console.log();
			console.log('Sending request...');
			console.log();

			const req = http.request(options, (res) => {
				console.log(`statusCode: ${res.statusCode}`)
				res.on('data', (d) => {
					console.log(JSON.parse(d))
				})
			})

			req.on('error', (error) => {
				console.error(error)
			})

			req.write(jsonData)
			req.end()

		}, 5000);
	})

