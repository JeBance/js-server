const fs = require('fs');
const http = require('http');
const openpgp = require('openpgp');
const process = require('process');
const readline = require('readline');
const securePGPstorage = require('secure-pgp-storage');
const nzfunc = require('nzfunc');
const letsconfig = require('letsconfig');

const config = new letsconfig({}, __dirname + '/../');
const sPGPs = new securePGPstorage();

let encryptedMessage = '';

let data = {
	request: {
		method: 'sendMessage',
		to: 'Alice',
		message: 'Hello!'
	}
};

process.stdout.write('\x1Bc');



const encrypt = new Promise((resolve, reject) => {
	try{
		(async () => {
			await sPGPs.decryptStorage(config.secureKey, config.passphrase)
			encryptedMessage = await sPGPs.encryptMessage(data.request.message, sPGPs.publicKeyArmored, true);
			data.request.message = encryptedMessage;
			let nonce = new Date().getTime();
			data.request.nonce = nonce;
			console.log(data);
			resolve(true);
		})();
	} catch(e) {
		console.log(e);
	}
});



encrypt.then((value) => {
	let messageSender = setInterval(async () => {
		console.log('\nSending request...');

		let jsonData = JSON.stringify(data);

		let options = {
			host: config.host,
			port: config.port,
			path: '/',
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Content-Length': jsonData.length
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

		req.write(jsonData);
		req.end();
	}, 5000);
});
