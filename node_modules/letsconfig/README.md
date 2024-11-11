# letsConfig
[letsConfig](https://jebance.github.io/letsconfig/) is a class for working with a configuration file.

**Table of Contents**

- [letsConfig](#letsconfig)
    - [Getting started](#getting-started)
        - [Node.js](#nodejs)
    - [Examples](#examples)
        - [Constructor](#constructor)
        - [writeConfigFile](#writeconfigfile)
    - [License](#license)


### letsConfig

* The letsConfig class allows you to automate work with the application configuration file.

* The `index.js` bundle works well in Node.js. It is used by default when you `require('letsconfig')` in Node.js.


### Getting started

#### Node.js

Install letsconfig using npm:

```sh
npm install letsconfig
```

And import it as a CommonJS module:

```js
const letsConfig = require('letsconfig');
```



### Examples

Here are some examples of how to use letsConfig.

#### Constructor

The `constructor` method takes the following optional parameters:

* `options` - an object with arbitrary data. Keys and values ​​will be assigned to the class during the initialization process. By default, it takes the value of an empty object: `options = {}`. If a configuration file with a JSON structure is read, the keys from this file will have priority for assigning variables.

* `dir` - a string specifying the absolute path to the directory containing the configuration file. Example: `/home/username/sites/somedomain/`.

* `fileName` - a string specifying the name of the configuration file with the `json` extension.

```js
let config = new letsConfig({
		host: 'localhost',
		port: 8000
	},
	'/home/username/sites/somedomain/',
	'configuration.json');
console.log(config.host);
console.log(config.port);

// or

let conf = new letsConfig();
console.log(conf);
```

#### writeConfigFile

The `writeConfigFile` function writes the current class data to a JSON configuration file.

```js
config.writeConfigFile();
```


### License

[GNU Lesser General Public License](https://www.gnu.org/licenses/lgpl-3.0.en.html) (3.0 or any later version). Please take a look at the [LICENSE](LICENSE) file for more information.
