const fs = require('fs');
const { hasJsonStructure } = require('nzfunc');

class letsConfig {
	dir;
	fileName;

	constructor(options = {}, dir = (__dirname + '/'), fileName = 'config.json') {
		try {
			this.dir = dir;
			this.fileName = fileName;
			let contents = fs.readFileSync(this.dir + this.fileName);
			if (hasJsonStructure(contents.toString()) === true) {
				options = JSON.parse(contents);
			} else {
				throw new Error('The file does not have a JSON structure!');
			}
		} catch (e) {
			console.log(`Could not read config.json file: ${e}`);
		}

		let keys = Object.keys(options);
		for (let i = 0, l = keys.length; i < l; i++) {
			this[keys[i]] = options[keys[i]];
		}
	}

	writeConfigFile() {
		let config = {};
		let keys = Object.keys(this);
		for (let i = 0, l = keys.length; i < l; i++) {
			if ((keys[i] !== 'dir') && (keys[i] !== 'fileName')) config[keys[i]] = this[keys[i]];
		}
		fs.writeFileSync(this.dir + this.fileName, JSON.stringify(config));
	}

}

module.exports = letsConfig;
