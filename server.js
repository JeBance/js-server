const VERSION = '0.3.15';
const fs = require('fs');
const http = require('http');
const openpgp = require('openpgp');
const process = require('process');
const readline = require('readline');
const nzlib = require('nzlib');
//import nzlib from "https://code4fukui.github.io/minimalistic-assert/index.js";

const paramUsername = process.argv[2];
const paramEmail = process.argv[3];
const paramPassphrase = process.argv[4];

let existsFileConfig = true;
let existsDirDB = true;
let config;
let indexFile;
let faviconFile;





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
	if (nzlib.hasJsonStructure(contents.toString()) === true) {
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
	console.log('\x1b[2m%s\x1b[0m', req.method, req.url);
	res.setHeader('Content-Type', 'application/json');

	if (req.method == 'POST') {

		const buffers = [];
		for await (const chunk of req) {
			buffers.push(chunk);
		}

		const data = Buffer.concat(buffers).toString();
		console.log(data);
		if (nzlib.hasJsonStructure(data) === true) {
			let request = JSON.parse(data);
			console.log(request);
			if ((request.hasOwnProperty('request') === true)
			&& (request.hasOwnProperty('signature') === true)) {
				if (request.request == 'sendMessage') {
					if ((request.hasOwnProperty('from') === true)
					&& (request.hasOwnProperty('to') === true)) {
						// записываем сообщение в бд и отправляем идентификатор сообщения
						// отправляем сообщение пяти нодам
					} else {
						res.writeHead(500);
						res.end(JSON.stringify({error:'Invalid request'}));
					}
				} else if (request.request == 'getNewMessage') {
					// проверяем подпись клиента и отдаём его сообщения
					res.writeHead(200);
					res.end(JSON.stringify({result:'Data successfully received'}));
				} else if (request.request == 'deleteMessage') {
					if (request.hasOwnProperty('messages') === true) {
						// проверяем подпись клиента и удаляем массив сообщений
						// отправляем сообщение пяти нодам
					} else {
						res.writeHead(500);
						res.end(JSON.stringify({error:'Invalid request'}));
					}
				} else {
					res.writeHead(500);
					res.end(JSON.stringify({error:'Invalid request'}));
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
				res.end(JSON.stringify({error:'Invalid request'}));
			}
		} else {
			res.writeHead(500);
			res.end(JSON.stringify({error:'Invalid request'}));
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
nzlib.HMAC('567890', 'Hello!')
	.then((value) => {
		console.log(value);
	})
*/