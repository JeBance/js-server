const openpgp = require('openpgp');

class sPGPs {
	nickname;
	email;
	fingerprint;
	publicKeyArmored;
	#privateKeyArmored;
	#publicKey;
	#privateKey;
	#passphrase;

	async createStorage(name, email, passphrase) {
		try {
			const { privateKey, publicKey } = await openpgp.generateKey({
				type: 'ecc', // Type of the key, defaults to ECC
				curve: 'curve25519', // ECC curve name, defaults to curve25519
				userIDs: [{ name: name, email: email }], // you can pass multiple user IDs
				passphrase: passphrase, // protects the private key
				format: 'armored' // output key format, defaults to 'armored' (other options: 'binary' or 'object')
			});

			this.publicKeyArmored = publicKey;
			this.#privateKeyArmored = privateKey;
			this.#publicKey = await openpgp.readKey({ armoredKey: publicKey });
			this.#privateKey = await openpgp.decryptKey({
				privateKey: await openpgp.readPrivateKey({ armoredKey: privateKey }),
				passphrase
			});
			this.#passphrase = passphrase;
			this.fingerprint = (this.#publicKey.getFingerprint());
			this.nickname = this.#publicKey.users[0].userID.name;
			this.email = this.#publicKey.users[0].userID.email;
		} catch(e) {
			console.log(e);
		}
	}

	hasJsonStructure(string) {
		if (typeof string !== 'string') return false;
		try {
			const result = JSON.parse(string);
			const type = Object.prototype.toString.call(result);
			return type === '[object Object]' 
				|| type === '[object Array]';
		} catch(e) {
			console.log(e);
		}
		return false;
	}

	async readKey(publicKeyArmored) {
		try {
			let key = await openpgp.readKey({ armoredKey: publicKeyArmored });
			return key;
		} catch(e) {
			console.log(e);
		}
		return false;
	}

	async checkMessage(data) {
		try {
			await openpgp.readMessage({ armoredMessage: data });
			return true;
		} catch(e) {
			console.log(e);
		}
		return false;
	}

	checkAllData() {
		let check;
		((this.nickname)
		&& (this.email)
		&& (this.fingerprint)
		&& (this.publicKeyArmored)
		&& (this.#privateKeyArmored)
		&& (this.#publicKey)
		&& (this.#privateKey)
		&& (this.#passphrase)) ? check = true : check = false;
		return check;
	}

	eraseAllData() {
		this.nickname = '';
		this.email = '';
		this.fingerprint = '';
		this.publicKeyArmored = '';
		this.#privateKeyArmored = '';
		this.#publicKey = '';
		this.#privateKey = '';
		this.#passphrase = '';
	}

	async encryptStorage() {
		try {
			const string = JSON.stringify({
				publicKey: this.publicKeyArmored,
				privateKey: this.#privateKeyArmored
			});
			const encrypted = await openpgp.encrypt({
				message: await openpgp.createMessage({ text: string }),
				passwords: [ this.#passphrase ],
				config: { preferredCompressionAlgorithm: openpgp.enums.compression.zlib }
			});
			return encrypted;
		} catch(e) {
			console.log(e);
		}
		return false;
	}

	async generateSecureFile() {
		const encrypted = await this.encryptStorage();
		const fileHref = 'data:application/pgp-encrypted,' + encodeURIComponent(encrypted);
		return fileHref;
	}
	
	async decryptStorage(data, passphrase) {
		try {
			const { data: decrypted } = await openpgp.decrypt({
				message: await openpgp.readMessage({ armoredMessage: data }),
				passwords: [ passphrase ],
			});
			if (this.hasJsonStructure(decrypted)) {
				const parseData = JSON.parse(decrypted);
				this.#publicKey = await openpgp.readKey({ armoredKey: parseData.publicKey });
				this.fingerprint = this.#publicKey.getFingerprint();
				this.nickname = this.#publicKey.users[0].userID.name;
				this.email = this.#publicKey.users[0].userID.email;
				this.#privateKey = await openpgp.decryptKey({
					privateKey: await openpgp.readPrivateKey({ armoredKey: parseData.privateKey }),
					passphrase
				});
				this.publicKeyArmored = parseData.publicKey;
				this.#privateKeyArmored = parseData.privateKey;
				this.#passphrase = passphrase;
				return true;
			} else {
				console.log('Error: Invalid container structure');
			}
		} catch(e) {
			console.log(e);
		}
		return false;
	}

	async encryptMessage(string, recipientPublicKeyArmored, signature = null) {
		try {
			let encrypted;
			const publicKey = await openpgp.readKey({ armoredKey: recipientPublicKeyArmored });
			const privateKey = this.#privateKey;
			if (signature === null) {
				encrypted = await openpgp.encrypt({
					message: await openpgp.createMessage({ text: string }),	// input as Message object
					encryptionKeys: publicKey
				});
			} else {
				encrypted = await openpgp.encrypt({
					message: await openpgp.createMessage({ text: string }),	// input as Message object
					encryptionKeys: publicKey,
					signingKeys: privateKey		// optional
				});
			}
			return encrypted;
		} catch(e) {
			console.log(e);
		}
		return false;
	}

	async decryptMessage(encrypted, senderPublicKeyArmored = null) {
		try {
			const privateKey = this.#privateKey;
			const message = await openpgp.readMessage({
				armoredMessage: encrypted	// parse armored message
			});
			let decrypted = {};
			if (senderPublicKeyArmored === null) {
				decrypted = await openpgp.decrypt({
					message,
					decryptionKeys: privateKey
				});
			} else {
				const publicKey = await openpgp.readKey({ armoredKey: senderPublicKeyArmored });
				decrypted = await openpgp.decrypt({
					message,
					verificationKeys: publicKey,	// optional
					decryptionKeys: privateKey
				});
			}
			return decrypted;
		} catch(e) {
			console.log(e);
		}
		return false;
	}

	async encryptMessageSymmetricallyWithCompression(string, passphrase) {
		try {
			const encrypted = await openpgp.encrypt({
				message: await openpgp.createMessage({ text: string }),
				passwords: [ passphrase ],
				config: { preferredCompressionAlgorithm: openpgp.enums.compression.zlib }
			});
			return encrypted;
		} catch(e) {
			console.log(e);
		}
		return false;
	}

	async decryptMessageSymmetricallyWithCompression(data, passphrase) {
		try {
			const { data: decrypted } = await openpgp.decrypt({
				message: await openpgp.readMessage({ armoredMessage: data }),
				passwords: [ passphrase ],
			});
			return decrypted;
		} catch(e) {
			console.log(e);
		}
		return false;
	}
}

module.exports = sPGPs;
