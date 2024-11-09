const fs = require('fs');

class nzfsdb {
	path;

	constructor(path = (__dirname + '/')) {
		this.path = path;
	}

	validateName(name) {
		try {
			const regex = /[<>^:"\/\\|?*\x00-\x1F]|^(?:aux|con|clock\$|nul|prn|com[1-9]|lpt[1-9])$/i;
			return !regex.test(name);
		} catch(e) {
			console.log(e);
			return false;
		}
	}
	
	stat(path) {
		try {
			fs.statSync(path);
			return true;
		} catch {
			return false;
		}
	}

	mkdir(dir) {
		if (!this.stat(dir)) {
			try {
				fs.mkdirSync(dir);
				return true;
			} catch(e) {
				console.log('\x1b[1m%s\x1b[0m', `Failed to create directory:`, e);
				return false;
			}
		}
		return true;
	}

	mkpath(path) {
		let arrayOfDirs;
		arrayOfDirs = path.split('/');
		path = '/';
		let keys = Object.keys(arrayOfDirs);
		for (let i = 0, l = keys.length; i < l; i++) {
			if (arrayOfDirs[keys[i]].length > 0) {
				if ((this.validateName(arrayOfDirs[keys[i]])) === true) {
					// validation was successful
					path += arrayOfDirs[keys[i]] + '/';
					if (!fs.existsSync(path)) {
						if (!this.mkdir(path)) return false;
					}
				} else {
					console.log(arrayOfDirs[keys[i]], '- The directory name is invalid');
					return false;
				}
			}
		}
		return path;
	}

	checkPath(path = null) {
		try {
			if (path === null) {
				path = this.path;
			} else if (typeof path === 'string') {
				path = this.path + path;
			} else {
				return false;
			}
			try {
				if (!fs.existsSync(path)) throw new Error();
			} catch(e) {
				if (!this.mkpath(path)) return false;
			}
			if (path.slice(-1) !== '/') path += '/';
			return path;
		} catch(e) {
			console.log('\x1b[1m%s\x1b[0m', `Failed to check path:`, e);
			return false;
		}
	}

	checkExists(path = null, file = null) {
		try {
			path = this.checkPath(path);
			if (!path) return false;

			if (file !== null) {
				if ((this.validateName(file)) === true) {
					if (fs.existsSync(path + file)) {
						return {path, file};
					} else {
						return false;
					}
				} else {
					console.log(file, '- The file name is invalid');
					return false;
				}
			}

			return {path, file};

		} catch(e) {
			console.log('\x1b[1m%s\x1b[0m', `Failed to check exists:`, e);
			return false;
		}
	}

	read(path = null, file = null) {
		let obj = this.checkExists(path, file) || false;
		let result = {};
		try {
			if (obj) {
				if (obj.file === null) {
					let files = fs.readdirSync(obj.path);
					let j = 0;
					for (var i in files) {
						var name = obj.path + files[i];
						if (!fs.statSync(name).isDirectory()) {
							result[j] = files[i];
							j++;
						}
					}
					return result;
				} else if (typeof obj.file === 'string') {
					result = fs.readFileSync(obj.path + obj.file, 'utf8');
				} else {
					return false;
				}
			} else {
				return false;
			}
		} catch(e) {
			console.log(e);
			return false;
		}
		return result;
	}

	write(path = null, file = null, string = '') {
		let obj = this.checkExists(path, null) || false;
		try {
			if ((obj)
			&& ((this.validateName(file)) === true)
			&& (typeof string === 'string')) {
				fs.writeFileSync(obj.path + file, string);
				return true;
			} else {
				return false;
			}
		} catch(e) {
			console.log(e);
			return false;
		}
	}

	delete(path = null, file = null) {
		let obj = this.checkExists(path, file) || false;
		let result = true;
		try {
			if (obj) {
				if (obj.file === null) {
					fs.rmSync(obj.path, { recursive: true });
					if (this.stat(obj.path)) return false;
				} else if (typeof obj.file === 'string') {
					fs.unlinkSync(obj.path + obj.file);
					if (this.checkExists(path, obj.file)) return false;
				} else {
					return false;
				}
			} else {
				return false;
			}
		} catch(e) {
			console.log(e);
			return false;
		}
		return result;
	}

}

module.exports = nzfsdb;
