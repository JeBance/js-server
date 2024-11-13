const path = __dirname;
const letsconfig = require('letsconfig');
const config = new letsconfig({
	host: '127.0.0.1',
	port: 28262,
	DB: '/DB/',
	path: path,
	passphrase: null,
	secureKey: null
}, path, '/config.json');

const nzfsdb = require('nzfsdb');
const DB = new nzfsdb(path + config.DB);
if (!DB.checkExists()) process.exit(1);

const fs = require('fs');
const http = require('http');
const URL = require('url');
const process = require('process');
const { networkInterfaces } = require('os');
const securePGPstorage = require('secure-pgp-storage');

const { getHASH,
		hasJsonStructure,
		isUrlValid,
		isIPv4withTCPportValid,
		doRequest,
		getResponse } = require('nzfunc');

let getProgramFiles = (path) => {
	try {
		let files = { index: {}, favicon: {} };
		files.index = fs.readFileSync(path + '/index.html');
		files.favicon = fs.readFileSync(path + '/favicon.ico');
		return files;
	} catch(e) {
		console.error('\x1b[1m%s\x1b[0m', `${e}`);
		process.exit(1);
	}
}
const files = getProgramFiles(path);

const PGP = new securePGPstorage();

const param = {
	username: process.argv[2],
	email: process.argv[3],
	passphrase: process.argv[4]
}
// when you generate keychain
// if you see:
// error:25066067:DSO support routines:dlfcn_load:could not load the shared library
// then run:
// export OPENSSL_CONF=/dev/null

process.stdout.write('\x1Bc');
console.log('\x1b[7m%s\x1b[0m', 'nzserver');
console.log(process.platform + '/' + process.arch);
console.log('pid ' + process.ppid);

const nznode = require('nznode');
let NODE = new nznode(config, DB, PGP);

let knownMessages = JSON.parse(DB.read(null, 'messages.json'));
// {"0f796b91e999447860b8dab1efb1af72":1731149821909,"f6c45a2fe5f5c9f7678e1b49dc4238e9":1731150123697}
if (!knownMessages) knownMessages = {};



const requestListener = (async (req, res) => {
	let nonce = new Date().getTime();
//	console.log('\x1b[2m%s\x1b[0m', req.method, req.url);
	res.setHeader('Content-Type', 'application/json');

	if (req.method == 'POST') {

		const buffers = [];
		for await (const chunk of req) {
			buffers.push(chunk);
		}
		const data = Buffer.concat(buffers).toString();
		let hash = getHASH(data, 'md5');

		// command messages (for interaction between nodes)
		if (hasJsonStructure(data) === true) {
			res.writeHead(200);
			res.end(JSON.stringify({result:'Data successfully received'}));
			req = JSON.parse(data);

			// handshake
			if (req.hasOwnProperty('handshake') === true) {
				let decrypted = await PGP.decryptMessage(req.handshake);

				if (decrypted) try {
					let senderKeyID, senderPublicKeyArmored;
					senderKeyID = decrypted.signatures[0].keyID.toHex();
					if (NODE.nodes[senderKeyID]) {
						senderPublicKeyArmored = DB.read('nodes', senderKeyID);
						decrypted = await PGP.decryptMessage(req.handshake, senderPublicKeyArmored);
						await decrypted.signatures[0].verified; // throws on invalid signature
					}
					// update node key
					if (hasJsonStructure(decrypted.data) === true) {
						decrypted = JSON.parse(decrypted.data);
						if ((decrypted.hasOwnProperty('host') === true)
						&& (decrypted.hasOwnProperty('port') === true)) {
							let info = await NODE.getInfo({
								host: decrypted.host,
								port: decrypted.port
							});
							if (info.publicKey) {
								let key = await PGP.readKey(info.publicKey);
								if (key) {
									newSenderKeyID = key.getKeyID().toHex();
									if (((NODE.nodes[senderKeyID]) && (senderKeyID !== newSenderKeyID))
									|| (!NODE.nodes[senderKeyID])) {
										await NODE.add({
											keyID: newSenderKeyID,
											host: decrypted.host,
											port: decrypted.port,
											ping: ping,
											publicKey: info.publicKey
										});
									}
									if ((NODE.nodes[senderKeyID])
									&& (senderKeyID !== newSenderKeyID)) {
										await NODE.remove(senderKeyID);
									}
								}
							}
						}
					}
				} catch(e) {
					console.log(e);
				}

			// newMessage
			} else if ((req.hasOwnProperty('newMessage') === true)
			&& (req.newMessage.hasOwnProperty('hash') === true)
			&& (req.newMessage.hasOwnProperty('message') === true)
			&& (req.newMessage.hasOwnProperty('timestamp') === true)
			&& ((await DB.validateName(req.newMessage.hash)) === true)
			&& (Number.isInteger(req.newMessage.timestamp))
			&& (req.newMessage.hash === getHASH(req.newMessage.message, 'md5'))
			&& (!knownMessages[req.newMessage.hash])) {
				let currentTime = new Date().getTime();
				if (((await PGP.checkMessage(req.newMessage.message)) === true)
				&& (req.newMessage.timestamp > (currentTime - 900000))
				&& (req.newMessage.timestamp < currentTime)) {
					knownMessages[req.newMessage.hash] = req.newMessage.timestamp;
					await DB.write('messages', req.newMessage.hash, req.newMessage.message);
					await DB.write(null, 'messages.json', JSON.stringify(knownMessages));
					await NODE.sendMessageToAll({
						newMessage: {
							hash: req.newMessage.hash,
							timestamp: req.newMessage.timestamp,
							message: req.newMessage.message
						}
					});
				}
			}

		// encrypted messages (just save and give)
		} else if ((await PGP.checkMessage(data)) === true) {
			res.writeHead(200);
			res.end(JSON.stringify({result:'Data successfully received'}));
			if (!knownMessages[hash]) {
				console.log('\x1b[1m%s\x1b[0m', 'New message:', hash + ':', nonce);
				knownMessages[hash] = nonce;
				await DB.write('messages', hash, data);
				await DB.write(null, 'messages.json', JSON.stringify(knownMessages));
				await NODE.sendMessageToAll({
					newMessage: {
						hash: hash,
						timestamp: nonce,
						message: data
					}
				});
			}

		} else {
			res.writeHead(500);
			res.end(JSON.stringify({error:'Invalid request'}));
		}

	} else {

		let url = (req.url).split('?');
		let args = {};
		if (typeof url[1] === 'string') {
			args = url[1].split('&');
		} else {
			args = false;
		}

		switch (url[0]) {
			case '/':
			case '/index.html':
				res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'});
				res.end(files.index);
				break
			case '/favicon.ico':
				res.writeHead(200, {'Content-Type': 'image/x-icon;'});
				res.end(files.favicon);
				break
			case '/info':
				let info = JSON.stringify({
					host: config.host,
					port: config.port,
					fingerprint: PGP.fingerprint,
					publicKey: PGP.publicKeyArmored
				});
				res.writeHead(200);
				res.end(info);
				break
			case '/getNodes':
				res.writeHead(200);
				res.end(JSON.stringify(NODE.nodes));
				break
			case '/getMessages':
				res.writeHead(200);
				res.end(JSON.stringify(knownMessages));
				break
			case '/getMessage':
				try {
					if ((args[0]) && (knownMessages[args[0]])) {
						res.writeHead(200);
						res.end(DB.read('messages', args[0]));
					} else {
						throw new Error();
					}
				} catch(e) {
					res.writeHead(404);
					res.end(JSON.stringify({error:'Resource not found'}));
				}
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
	try {
		(async () => {
			if ((param.username != null && typeof param.username !== "undefined")
			|| (param.email != null && typeof param.email !== "undefined")
			|| (param.passphrase != null && typeof param.passphrase !== "undefined")) {
				console.log('Generate keychain...');

				(async () => {
					await PGP.createStorage(param.username, param.email, param.passphrase);
					console.log('publicKey generated successfully ✔️');
					console.log('privateKey generated successfully ✔️');
					config.passphrase = param.passphrase;
					let encryptedStorage = await PGP.encryptStorage();
					config.secureKey = encryptedStorage;
					config.writeConfigFile();
					console.log('Keychain saved successfully ✔️');
					resolve(true);
				})();

			} else {

				console.log('Checking keychain...')
				if ((await PGP.checkMessage(config.secureKey))
				&& (await PGP.decryptStorage(config.secureKey, config.passphrase))) {
					console.log('Keychain available ✔️');
					resolve(true);
				} else {
					console.log('\x1b[1m%s\x1b[0m', 'Missing keychain ❌');
					console.error('\x1b[1m%s\x1b[0m', 'Run the server with the Nickname, Email and Passphrase parameters. For example, "node server.js MyNickname MyName@somemail.com MyPassphrase".');
					process.exit(1);
				}

			}
		})();
	} catch(e) {
		console.error('\x1b[1m%s\x1b[0m', `Failed to create keychain: ${e}`);
		process.exit(1);
	}
});



checkingKeychain
	.then((value) => {
		server.listen(config.port, config.host, () => {
			console.log('\x1b[7m%s\x1b[0m', `Server is running on http://${config.host}:${config.port}`);
		});
	})



let checkingMessages = setInterval(async () => {
	let currentTime = new Date().getTime();
	let keys = Object.keys(knownMessages);
	for (let i = 0, l = keys.length; i < l; i++) {
		if (knownMessages[keys[i]] < (currentTime - 900000)) {	// 15 min
			// deleting old messages
			await DB.delete('messages', knownMessages[keys[i]]);
			delete knownMessages[keys[i]]
		}
	}
}, 10000);



let checkingNodes = setInterval(async () => {
	await NODE.checkingNodes();
}, 10000);

let searchingNodes = setInterval(async () => {
	await NODE.searchingNodes();
}, 1000);

