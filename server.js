const VERSION = '0.3.15';
const fs = require('fs');
const http = require('http');
const openpgp = require('openpgp');
const process = require('process');
const readline = require('readline');

const paramUsername = process.argv[2];
const paramEmail = process.argv[3];
const paramPassphrase = process.argv[4];
// when you generate keychain
// if you see:
// error:25066067:DSO support routines:dlfcn_load:could not load the shared library
// then run:
// export OPENSSL_CONF=/dev/null

let existsFileConfig = true;
let existsDirDB = true;
let config;
let indexFile;
let faviconFile;

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

HMAC = async function HMAC(key, message) {
	const g = str => new Uint8Array([...unescape(encodeURIComponent(str))].map(c => c.charCodeAt(0))),
	k = g(key),
	m = g(message),
	c = await crypto.subtle.importKey('raw', k, { name: 'HMAC', hash: 'SHA-512' }, true, ['sign']),
	s = await crypto.subtle.sign('HMAC', c, m);
	return btoa(String.fromCharCode(...new Uint8Array(s)))
}

process.stdout.write('\x1Bc');
console.log('VERSION: ' + VERSION);
console.log(process.platform + '/' + process.arch);
console.log('pid ' + process.ppid);
console.log();

try {
	console.log('Checking "index.html" file...');
	indexFile = fs.readFileSync(__dirname + '/index.html');
	console.log('\x1b[1m%s\x1b[0m', '"index.html" has been read ✔️');
} catch (err) {
	console.error('\x1b[1m%s\x1b[0m', `Could not read index.html file: ${err}`);
	process.exit(1);
}

console.log();

try {
	console.log('Checking "favicon.ico" file...');
	faviconFile = fs.readFileSync(__dirname + '/favicon.ico');
	console.log('\x1b[1m%s\x1b[0m', '"favicon.ico" has been read ✔️');
} catch (err) {
	console.error('\x1b[1m%s\x1b[0m', `Could not read favicon.ico file: ${err}`);
}

console.log();

try {
	console.log('Checking "config.json" file...');
	let contents = fs.readFileSync(__dirname + '/config.json');
	if (hasJsonStructure(contents.toString()) === true) {
		config = JSON.parse(contents);
		console.log('\x1b[1m%s\x1b[0m', '"config.json" has been read ✔️');
//		console.log(config);
	} else {
		existsFileConfig = false;
	}
} catch (err) {
	console.error(`Could not read config.json file: ${err}`);
	existsFileConfig = false;
}

if (existsFileConfig === false) try {
	config = {host:'localhost',port:8000,DB:'/DB/',fingerprint:null,passphrase:null,publicKey:null,privateKey:null};
	fs.writeFileSync(__dirname + '/config.json', JSON.stringify(config));
	let contents = fs.readFileSync(__dirname + '/config.json');
	config = JSON.parse(contents);
	console.log('\x1b[1m%s\x1b[0m', '"config.json" was generated successfully ✔️');
//	console.log(config);
} catch (err) {
	console.error(`Could not read config.json file: ${err}`);
	process.exit(1);
}

console.log();

try {
	console.log('Checking DB directory...');
	let statsDB = fs.statSync(__dirname + config['DB']);
	console.log('\x1b[1m%s\x1b[0m', 'DB directory exists ✔️');
} catch (err) {
	console.log('DB directory is missing ❌');
	existsDirDB = false;
}

if (existsDirDB === false) try {
	fs.mkdirSync(__dirname + config['DB']);
	console.log('\x1b[1m%s\x1b[0m', 'Directory successfully created ✔️');
	existsDirDB = true;
} catch (err) {
	console.error('\x1b[1m%s\x1b[0m', `Failed to create directory: ${err}`);
}

console.log();

const requestListener = (async (req, res) => {
//	console.log('\x1b[2m%s\x1b[0m', req.method, req.url);
	res.setHeader('Content-Type', 'application/json');

	if (req.method == 'POST') {

		const buffers = [];
		for await (const chunk of req) {
			buffers.push(chunk);
		}

		const data = Buffer.concat(buffers).toString();
//		console.log(data);
		if (hasJsonStructure(data) === true) {
			let request = JSON.parse(data);
//			console.log(request);
			if ((request.hasOwnProperty('request') === true)
			&& (request.hasOwnProperty('signature') === true)) {
				if (request.request.method == 'sendMessage') {
					if (request.request.hasOwnProperty('to') === true) {
						if (request.request.hasOwnProperty('message') === true) {
							// проверяем сообщение

							// у клиента и сервера временно одинаковые ключи
							const publicKey = await openpgp.readKey({ armoredKey: config['publicKey'] });
/*
							const cleartextMessage = request.signature;
							const signedMessage = await openpgp.readCleartextMessage({ cleartextMessage });
							const verificationResult = await openpgp.verify({
								message: signedMessage,
								verificationKeys: publicKey
							});
*/
							const message = await openpgp.createMessage({ text: JSON.stringify(request.request) });
							const detachedSignature = request.signature;
							const signature = await openpgp.readSignature({
								armoredSignature: detachedSignature // parse detached signature
							});
							const verificationResult = await openpgp.verify({
								message, // Message object
								signature,
								verificationKeys: publicKey
							});

							const { verified, keyID } = verificationResult.signatures[0];
							try {
								await verified; // throws on invalid signature
								console.log('Signed by key id ' + keyID.toHex());
							} catch (e) {
								throw new Error('Signature could not be verified: ' + e.message);
							}

							// записываем сообщение в бд и отправляем идентификатор сообщения
							// отправляем сообщение пяти нодам
							//////////////////////////////////
							res.writeHead(200);
							res.end(JSON.stringify({result:'Data successfully received'}));
						} else {
							res.writeHead(500);
							res.end(JSON.stringify({error:'Invalid request: "Message missing"'}));
						}
					} else {
						res.writeHead(500);
						res.end(JSON.stringify({error:'Invalid request: "Recipient not specified"'}));
					}
				} else if (request.request.method == 'getNewMessage') {
					// проверяем подпись клиента и отдаём его сообщения
					res.writeHead(200);
					res.end(JSON.stringify({result:'Data successfully received'}));
				} else if (request.request.method == 'deleteMessage') {
					if (request.hasOwnProperty('messages') === true) {
						// проверяем подпись клиента и удаляем массив сообщений
						// отправляем сообщение пяти нодам
					} else {
						res.writeHead(500);
						res.end(JSON.stringify({error:'Invalid request'}));
					}
				} else {
					res.writeHead(500);
					res.end(JSON.stringify({error:'Invalid request: "Unknown method"'}));
				}
/*
				try {
					const message = await openpgp.readMessage({ armoredMessage: request.request });
					console.log(message);
					const { data: decrypted, signatures } = await openpgp.decrypt({
						message,
						verificationKeys: config['publicKey'],
						decryptionKeys: config['privateKey']
					});
					console.log('decrypted' + decrypted);
					console.log('signatures' + signatures);
					await signatures[0].verified;
					let decodedJSON = JSON.parse(decrypted);
					console.log(decodedJSON);
				} catch(e) {
					console.log(e);
				}
*/
			} else {
				res.writeHead(500);
				res.end(JSON.stringify({error:'Invalid request: "One of the parameters is missing: request or signature"'}));
			}
		} else {
			res.writeHead(500);
			res.end(JSON.stringify({error:'Invalid request: "The request does not have a JSON structure"'}));
		}

	} else {

		switch (req.url) {
			case '/':
			case '/index.html':
				res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'});
				res.end(indexFile);
				break
			case '/favicon.ico':
				res.writeHead(200, {'Content-Type': 'image/x-icon;'});
				res.end(faviconFile);
				break
			case '/info':
				let info = JSON.stringify({
					host: config['host'],
					port: config['port'],
					fingerprint: config['fingerprint'],
					publicKey: config['publicKey']
				});
				res.writeHead(200);
				res.end(info);
				break
			default:
				res.writeHead(404);
				res.end(JSON.stringify({error:'Resource not found'}));
		}

	}
//	console.log(res.headers);
//	console.log('\x1b[2m%s\x1b[0m', res.getHeaders());
});

const server = http.createServer(requestListener);

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
			resolve(true);
		}
	} catch (err) {
		console.error('\x1b[1m%s\x1b[0m', `Failed to create keychain: ${err}`);
		process.exit(1);
	}

});

checkingKeychain
	.then((value) => {
		server.listen(config['port'], config['host'], () => {
			console.log('\x1b[7m%s\x1b[0m', `Server is running on http://${config['host']}:${config['port']}`);
		});
	})

/*
HMAC('567890', 'Hello!')
	.then((value) => {
		console.log(value);
	})
*/
