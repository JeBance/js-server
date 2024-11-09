const fs = require('fs');
const http = require('http');
const process = require('process');
const securePGPstorage = require('secure-pgp-storage');
const nzfunc = require('nzfunc');
const letsconfig = require('letsconfig');

const config = new letsconfig({}, __dirname + '/../');
const sPGPs = new securePGPstorage();

let url = '127.0.0.1' + ':' + config.port;
let jsonCommand = {	url: url };
let encryptedMessage = '';
let jsonReq = { handshake: '' };

process.stdout.write('\x1Bc');



const encrypt = new Promise((resolve, reject) => {
	try{
		(async () => {
			await sPGPs.decryptStorage(config.secureKey, config.passphrase)
			encryptedMessage = await sPGPs.encryptMessage(JSON.stringify(jsonCommand), sPGPs.publicKeyArmored, true);
			jsonReq.handshake = encryptedMessage;
			console.log(JSON.stringify(jsonReq));
			resolve(true);
		})();
	} catch(e) {
		console.log(e);
	}
});



encrypt.then((value) => {
	let messageSender = setInterval(async () => {
		console.log('\nSending request...');

		let options = {
			host: config.host,
			port: config.port,
			path: '/',
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Content-Length': (JSON.stringify(jsonReq)).length
			}
		};

		const req = http.request(options, (res) => {
			console.log(`statusCode: ${res.statusCode}`)
			res.on('data', (d) => {
				console.log(JSON.parse(d));
			})
		})

		req.on('error', (error) => {
			console.error(error);
		})

		req.write(JSON.stringify(jsonReq));
		req.end();
	}, 5000);
});
