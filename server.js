const VERSION = '0.3.15';
const fs = require('fs');
const http = require('http');
const URL = require('url');
const process = require('process');
const { networkInterfaces } = require('os');
const securePGPstorage = require('secure-pgp-storage');
const letsconfig = require('letsconfig');
const nzfunc = require('nzfunc');
const nzfsdb = require('nzfsdb');

const paramUsername = process.argv[2];
const paramEmail = process.argv[3];
const paramPassphrase = process.argv[4];
// when you generate keychain
// if you see:
// error:25066067:DSO support routines:dlfcn_load:could not load the shared library
// then run:
// export OPENSSL_CONF=/dev/null

process.stdout.write('\x1Bc');
console.log('\x1b[7m%s\x1b[0m', `nzserver`);
console.log('VERSION: ' + VERSION);
console.log(process.platform + '/' + process.arch);
console.log('pid ' + process.ppid);

const sPGPs = new securePGPstorage();

const config = new letsconfig({
	host: '127.0.0.1',
	port: 28262,
	DB: '/DB/',
	passphrase: null,
	secureKey: null,
	lastCheckedMessage: '0'
}, __dirname + '/');

const DB = new nzfsdb(__dirname + config.DB);
if (!DB.checkExists()) process.exit(1);

let knownNodes = JSON.parse(DB.read(null, 'nodes.json'));
// {"96c3a2e45d53a7c5":{"url":"127.0.0.1:28262","ping":4},"85c2a1e34d42a6c4":{"url":"http://google.com:28262","ping":26}}
if (!knownNodes) knownNodes = {};

let knownMessages = JSON.parse(DB.read(null, 'messages.json'));
// {"0f796b91e999447860b8dab1efb1af72":1731149821909,"f6c45a2fe5f5c9f7678e1b49dc4238e9":1731150123697}
if (!knownMessages) knownMessages = {};

let indexFile;
let faviconFile;

try {
	console.log('Checking "index.html" file...');
	indexFile = fs.readFileSync(__dirname + '/index.html');
	console.log('\x1b[1m%s\x1b[0m', '"index.html" has been read ✔️');
} catch(e) {
	console.error('\x1b[1m%s\x1b[0m', `Could not read index.html file: ${e}`);
	process.exit(1);
}

try {
	console.log('Checking "favicon.ico" file...');
	faviconFile = fs.readFileSync(__dirname + '/favicon.ico');
	console.log('\x1b[1m%s\x1b[0m', '"favicon.ico" has been read ✔️');
} catch(e) {
	console.error('\x1b[1m%s\x1b[0m', `Could not read favicon.ico file: ${e}`);
}



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
		let hash = nzfunc.getHASH(data, 'md5');

		// command messages
		if (nzfunc.hasJsonStructure(data) === true) {
			res.writeHead(200);
			res.end(JSON.stringify({result:'Data successfully received'}));
			req = JSON.parse(data);

			// handshake
			if (req.hasOwnProperty('handshake') === true) {
				let decrypted = await sPGPs.decryptMessage(req.handshake);
				if (decrypted) try {
					let senderKeyID, senderPublicKeyArmored;
					senderKeyID = decrypted.signatures[0].keyID.toHex();
					if (knownNodes[senderKeyID]) {
						senderPublicKeyArmored = DB.read('nodes', senderKeyID);
						decrypted = await sPGPs.decryptMessage(req.handshake, senderPublicKeyArmored);
						await decrypted.signatures[0].verified; // throws on invalid signature
					}
					// update node key
					if (nzfunc.hasJsonStructure(decrypted.data) === true) {
						decrypted = JSON.parse(decrypted.data);
						if ((decrypted.hasOwnProperty('url') === true)
						&& ((nzfunc.isUrlValid(decrypted.url))
						|| (nzfunc.isIPv4withTCPportValid(decrypted.url)))) {
							let addr = parseAddr(decrypted.url);
							if (addr) {
								let options = {
									host: addr.host,
									port: addr.port,
									path: '/info',
									method: 'GET'
								};
								let pingStart = new Date().getTime();
								let res = await nzfunc.doRequest(options);
								if (res.statusCode == 200) {
									let pingFinish = new Date().getTime();
									let pingTime = pingFinish - pingStart;
									let infoServer = JSON.parse(await nzfunc.getResponse(res));
									if (infoServer.publicKey) {
										let key = await sPGPs.readKey(infoServer.publicKey);
										if (key) {
											newSenderKeyID = key.getKeyID().toHex();
											if ((knownNodes[senderKeyID])
											&& (senderKeyID !== newSenderKeyID)) {
												DB.delete('nodes', senderKeyID);
												delete knownNodes[senderKeyID];
												console.log('\x1b[1m%s\x1b[0m', 'Delete node:', senderKeyID, knownNodes[senderKeyID].url, `(${pingTime} ms)`);
											}
											if (((knownNodes[senderKeyID])
											&& (senderKeyID !== newSenderKeyID)) || (!knownNodes[senderKeyID])) {
												DB.write('nodes', newSenderKeyID, infoServer.publicKey);
												knownNodes[newSenderKeyID] = {
													url: decrypted.url,
													ping: pingTime
												};
												console.log('\x1b[1m%s\x1b[0m', 'New node:', newSenderKeyID, decrypted.url, `(${pingTime} ms)`);
												DB.write(null, 'nodes.json', JSON.stringify(knownNodes));
											}
										}
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
			&& (!knownMessages[req.newMessage.hash])) {
				let currentTime = new Date().getTime();
				if (((await sPGPs.checkMessage(req.newMessage.message)) === true)
				&& (req.newMessage.timestamp > (currentTime - 900000))
				&& (req.newMessage.timestamp < currentTime)) {
					knownMessages[req.newMessage.hash] = req.newMessage.timestamp;
					DB.write('messages', req.newMessage.hash, req.newMessage.message);
					DB.write(null, 'messages.json', JSON.stringify(knownMessages));
					passMessageAllNodes({
						newMessage: {
							hash: req.newMessage.hash,
							timestamp: req.newMessage.timestamp,
							message: req.newMessage.message
						}
					});
				}
			}

		// encrypted messages
		} else if ((await sPGPs.checkMessage(data)) === true) {
			res.writeHead(200);
			res.end(JSON.stringify({result:'Data successfully received'}));
			if (!knownMessages[hash]) {
				knownMessages[hash] = nonce;
				DB.write('messages', hash, data);
				DB.write(null, 'messages.json', JSON.stringify(knownMessages));
				passMessageAllNodes({
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
				res.end(indexFile);
				break
			case '/favicon.ico':
				res.writeHead(200, {'Content-Type': 'image/x-icon;'});
				res.end(faviconFile);
				break
			case '/info':
				let info = JSON.stringify({
					host: config.host,
					port: config.port,
					fingerprint: sPGPs.fingerprint,
					publicKey: sPGPs.publicKeyArmored
				});
				res.writeHead(200);
				res.end(info);
				break
			case '/getNodes':
				res.writeHead(200);
				res.end(JSON.stringify(knownNodes));
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
			if ((paramUsername != null && typeof paramUsername !== "undefined")
			|| (paramEmail != null && typeof paramEmail !== "undefined")
			|| (paramPassphrase != null && typeof paramPassphrase !== "undefined")) {
				console.log('Generate keychain...');

				(async () => {
					await sPGPs.createStorage(paramUsername, paramEmail, paramPassphrase);
					console.log('publicKey generated successfully ✔️');
					console.log('privateKey generated successfully ✔️');
					config.passphrase = paramPassphrase;
					let encryptedStorage = await sPGPs.encryptStorage();
					config.secureKey = encryptedStorage;
					config.writeConfigFile();
					console.log('Keychain saved successfully ✔️');
					resolve(true);
				})();

			} else {

				console.log('Checking keychain...')
				if ((await sPGPs.checkMessage(config.secureKey))
				&& (await sPGPs.decryptStorage(config.secureKey, config.passphrase))) {
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
			DB.delete('messages', knownMessages[keys[i]]);
			delete knownMessages[keys[i]]
		}
	}
}, 10000);



let checkingNodes = setInterval(async () => {
	let addr = {};
	let options = {
		host: '',
		port: '',
		path: '/info',
		method: 'GET'
	};
	let publicKeyArmored = '';
	let keys = Object.keys(knownNodes);

	for (let i = 0, l = keys.length; i < l; i++) {
		addr = parseAddr(knownNodes[keys[i]].url)
		options.host = addr.host;
		options.port = addr.port;
		let pingStart = new Date().getTime();
		let res = await nzfunc.doRequest(options);
		if (res.statusCode == 200) {
			let pingFinish = new Date().getTime();
			let pingTime = pingFinish - pingStart;
			let infoServer = JSON.parse(await nzfunc.getResponse(res));
			publicKeyArmored = DB.read('nodes', keys[i]);
			if ((infoServer.publicKey) && (infoServer.publicKey === publicKeyArmored)) {
				knownNodes[keys[i]].ping = pingTime;
			} else {
				console.log('\x1b[1m%s\x1b[0m', 'Node removed:', keys[i], knownNodes[keys[i]].url);
				DB.delete('nodes', keys[i]);
				delete knownNodes[keys[i]];
				DB.write(null, 'nodes.json', JSON.stringify(knownNodes));
			}
		}

	}
}, 10000);



let searchingNodes = setInterval(async () => {
	const nets = networkInterfaces();
//	console.log(nets);
	const results = {}; // Or just '{}', an empty object

	for (const name of Object.keys(nets)) {
		for (const net of nets[name]) {
			// Skip over non-IPv4 and internal (i.e. 127.0.0.1) addresses
			// 'IPv4' is in Node <= 17, from 18 it's a number 4 or 6
			const familyV4Value = typeof net.family === 'string' ? 'IPv4' : 4
			if (net.family === familyV4Value && !net.internal) {
				if (!results[name]) {
					results[name] = [];
				}
				results[name].push(net.address);
				await pingAddresses(net.address);
			}
		}
	}

	console.log(results);

}, 10000);



let pingAddresses = async (address) => {
	let addr = address.split('.');
	let options = {
		host: '',
		port: '',
		path: '/info',
		method: 'GET'
	};
	let publicKeyArmored = '';
	for (let i = 106, l = 107; i < l; i++) {
		try {
			options.host = addr[0] + '.' + addr[1] + '.' + addr[2] + '.' + i;
			options.port = '28262';
//console.log(options.host + ':' + options.port);
			var pingStart = new Date().getTime();
			var res = await nzfunc.doRequest(options);
			if (res.statusCode == 200) {
				var pingFinish = new Date().getTime();
				var pingTime = pingFinish - pingStart;
				var infoNode = JSON.parse(await nzfunc.getResponse(res));
				if (infoNode.publicKey) {
//console.log(infoNode);
					var key = await sPGPs.readKey(infoNode.publicKey);
					if (key) {
						nodeKeyID = key.getKeyID().toHex();
//console.log(nodeKeyID);
//console.log(knownNodes[nodeKeyID]);
						if (knownNodes[nodeKeyID]) {
							publicKeyArmored = DB.read('nodes', nodeKeyID);
//console.log(publicKeyArmored);
							if (publicKeyArmored === infoNode.publicKey) {
//console.log(pingTime);
								knownNodes[nodeKeyID].ping = pingTime;
console.log(knownNodes[nodeKeyID].ping);
							} else {
								console.log('\x1b[1m%s\x1b[0m', 'Node removed:', nodeKeyID, knownNodes[nodeKeyID].url);
								DB.delete('nodes', nodeKeyID);
								delete knownNodes[nodeKeyID];
								DB.write(null, 'nodes.json', JSON.stringify(knownNodes));
							}
						} else {
							var myAddr = config.host + ':' + config.port;
console.log(myAddr);
							var jsonCommand = {	url: myAddr };
console.log(jsonCommand);
							var encrypted = await sPGPs.encryptMessage(JSON.stringify(jsonCommand), infoNode.publicKey, true);
console.log(encrypted);
							passMessageOneNode({handshake: encrypted}, options);
							DB.write('nodes', nodeKeyID, infoNode.publicKey);
							knownNodes[nodeKeyID].url = options.host + ':' + options.port;
							knownNodes[nodeKeyID].ping = pingTime;
							DB.write(null, 'nodes.json', JSON.stringify(knownNodes));
							console.log('\x1b[1m%s\x1b[0m', 'New node:', nodeKeyID, knownNodes[nodeKeyID].url, `(${knownNodes[nodeKeyID].ping} ms)`);
						}
					}
				}
//				process.exit(1);
			}
		} catch(e) {
//			console.log(e);
		}
	}
};



let parseAddr = (string) => {
	let result = {};
	try {
		if (nzfunc.isIPv4withTCPportValid(string)) {
			ip = (string).split(':');
			result.host = ip[0];
			result.port = ip[1];
		} else if (nzfunc.isUrlValid(string)) {
			url = URL.parse(string);
			result.host = url.hostname;
			result.port = url.port;
		} else {
			return false;
		}
		return result;
	} catch(e) {
		console.log(e);
	}
	return false;
}



let passMessageOneNode = async (obj, addr = { host: '127.0.0.1', port: '28262' }) => {
	let options = {
		host: addr.host,
		port: addr.port,
		path: '/',
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Content-Length': (JSON.stringify(obj)).length
		}
	};
	nzfunc.doRequest(options, JSON.stringify(obj));
}



let passMessageAllNodes = async (obj) => {
	let addr = {};
	let options = {
		host: '',
		port: '',
		path: '/',
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Content-Length': (JSON.stringify(obj)).length
		}
	};
	let keys = Object.keys(knownNodes);
	for (let i = 0, l = keys.length; i < l; i++) {
		addr = parseAddr(knownNodes[keys[i]].url)
		options.host = addr.host;
		options.port = addr.port;
		nzfunc.doRequest(options, JSON.stringify(obj));
	}
}
