const fs = require('fs');
const nzfunc = require('nzfunc');

class letsConfig {
	dir;
	fileName;

	constructor(options = {}, dir = (__dirname + '/'), fileName = 'config.json') {
		try {
			this.dir = dir;
			this.fileName = fileName;
			//console.log('Checking config file:', dir + fileName);
			let contents = fs.readFileSync(this.dir + this.fileName);
			if (nzfunc.hasJsonStructure(contents.toString()) === true) {
				// config has been read
				options = JSON.parse(contents);
				// console.log(options);
			} else {
				throw new Error('The file does not have a JSON structure!');
			}
		} catch (e) {
			// console.log(`Could not read config.json file: ${e}`);
			// console.log(options);
		}

		let keys = Object.keys(options);
		// console.log(keys);
		for (let i = 0, l = keys.length; i < l; i++) {
			this[keys[i]] = options[keys[i]];
		}
		// console.log(this);
	}

	writeConfigFile() {
		fs.writeFileSync(this.dir + this.fileName, JSON.stringify(this));
	}

}

module.exports = letsConfig;
