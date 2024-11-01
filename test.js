const fs = require('fs');
const http = require('http');
const openpgp = require('openpgp');
const process = require('process');
const readline = require('readline');
const nzlib = require('nzlib');

let config;

let data = JSON.stringify({
	request: 'sendMessage',
	message: 'Hello!'
});

const options = {
	host: 'localhost',
	port: 8000,
	path: '/',
	method: 'POST',
	headers: {
		'Content-Type': 'application/json',
		'Content-Length': data.length
	}
};

try {
	console.log('Checking "config.json" file...');
	let contents = fs.readFileSync(__dirname + '/config.json');
	if (nzlib.hasJsonStructure(contents.toString()) === true) {
		config = JSON.parse(contents);
		console.log('\x1b[1m%s\x1b[0m', '"config.json" has been read ✔️');
//		console.log(config);
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
			resolve(true);
		}
	} catch (err) {
		console.error('\x1b[1m%s\x1b[0m', `Failed to create keychain: ${err}`);
		process.exit(1);
	}

});

checkingKeychain
	.then((value) => {
		let timerId = setInterval(async () => {

			const req = http.request(options, (res) => {
				console.log(`statusCode: ${res.statusCode}`)
				res.on('data', (d) => {
					console.log(JSON.parse(d))
				})
			})

			req.on('error', (error) => {
				console.error(error)
			})

			req.write(data)
			req.end()

		}, 10000);
	})

