const http = require('http');
const crypto = require('crypto');

module.exports.hasJsonStructure = function (string) {
	if (typeof string !== 'string') return false;
	try {
		const result = JSON.parse(string);
		const type = Object.prototype.toString.call(result);
		return type === '[object Object]' 
			|| type === '[object Array]';
	} catch(e) {
//		console.log(e);
	}
	return false;
};

module.exports.getHASH = function (string, algorithm) {
	let hash = crypto.createHash('md5').update(string).digest('hex');
	return hash;
};

module.exports.getHMAC = function (string, algorithm, secret) {
	try {
		let hash, hmac;
		hmac = crypto.createHmac(algorithm, secret);    
		hmac.write(string);
		hmac.end();
		hash = hmac.read().toString('hex');
		return hash;
	} catch(e) {
		console.log(e);
	}
	return false;
};

module.exports.isUrlValid = function (string) {
	try {
		const regex = /(http(s)?:\/\/.)?(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)/g;
		return regex.test(string);
	} catch(e) {
		console.log(e);
		return false;
	}
};

module.exports.isIPv4withTCPportValid = function (string) {
	try {
		const regex = /^((?:(?:\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])(?:\.(?!\:)|)){4})\:(?!0)(\d{1,4}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$/g;
		return regex.test(string);
	} catch(e) {
		console.log(e);
		return false;
	}
};

module.exports.doRequest = function (options, data = null) {
	return new Promise ((resolve, reject) => {
		let req = http.request(options);

		req.on('response', res => {
			resolve(res);
		});

		req.on('error', err => {
			reject(err);
		});

		if (data !== null) req.write(data);
		req.end();
	}); 
}

module.exports.getResponse = function (res) {
	return new Promise ((resolve, reject) => {
		res.on('data', (d) => {
			resolve(d);
		});
	});
}
