# nzfunc
[nzfunc](https://jebance.github.io/nzfunc/) is a function library.

**Table of Contents**

- [nzfunc](#nzfunc)
    - [Getting started](#getting-started)
        - [Node.js](#nodejs)
    - [Functions](#functions)
        - [hasJsonStructure](#hasJsonStructure)
        - [getHASH](#getHASH)
        - [getHMAC](#getHMAC)
        - [isUrlValid](#isUrlValid)
        - [isIPv4withTCPportValid](#isIPv4withTCPportValid)
        - [doRequest and getResponse](#doRequest-and-getResponse)
    - [License](#license)


### nzfunc

* The nzfunc library is designed to minimize code. The library will be expanded. You can suggest your function to be added to this module.

* The `index.js` bundle works well in Node.js. It is used by default when you `require('nzfunc')` in Node.js.


### Getting started

#### Node.js

Install nzfunc using npm:

```sh
npm install nzfunc
```

And import it as a CommonJS module:

```js
const nzfunc = require('nzfunc');
```


### Functions

Here is a description of how the functions work.

#### hasJsonStructure

The `hasJsonStructure` function checks the JSON structure of the received string.

```js
let string = '{"a":"12","b":13,"c":null}';
if (nzfunc.hasJsonStructure(string) === true) {
	console.log('String have a JSON structure');
} else {
	console.log('String does not have a JSON structure');
}
```

#### getHASH

The `getHASH` function returns the hash of the passed string.

```js
console.log(nzfunc.getHASH('Hello'));
```

#### getHMAC

The `getHMAC` function returns hash-based message authentication code.

```js
console.log(nzfunc.getHMAC('Hello', 'sha256', 'secret'));
```

#### isUrlValid

The `isUrlValid` function checks the url address passed in the string for validity.

```js
console.log('Checking URL validity:');
console.log('TRUE /////////////////////////////////////////////////////////////');
console.log(nzfunc.isUrlValid('google.com'), 'google.com');
console.log(nzfunc.isUrlValid('http://google.com'), 'http://google.com');
console.log(nzfunc.isUrlValid('https://google.com'), 'https://google.com');
console.log(nzfunc.isUrlValid('http://www.google.com'), 'http://www.google.com');
console.log(nzfunc.isUrlValid('http://www.google.com/'), 'http://www.google.com/');
console.log(nzfunc.isUrlValid('http://www.google.com:8000'), 'http://www.google.com:8000');
console.log(nzfunc.isUrlValid('http://www.google.com:8000/'), 'http://www.google.com:8000/');
console.log(nzfunc.isUrlValid('http://www.google.com:8000/some'), 'http://www.google.com:8000/some');
console.log(nzfunc.isUrlValid('http://www.google.com:8000/some?'), 'http://www.google.com:8000/some?');
console.log(nzfunc.isUrlValid('http://www.google.com:8000/some?arg'), 'http://www.google.com:8000/some?arg');
console.log(nzfunc.isUrlValid('http://www.google.com:8000/some?a=%bc&b=%ef&c=%H'), 'http://www.google.com:8000/some?a=%bc&b=%ef&c=%H');
console.log('FALSE ////////////////////////////////////////////////////////////');
console.log(nzfunc.isUrlValid('12.34.56.78'), '12.34.56.78');
console.log(nzfunc.isUrlValid('12.34.56.78:8000'), '12.34.56.78:8000');
console.log(nzfunc.isUrlValid('tg://t.me'), 'tg://t.me');
console.log(nzfunc.isUrlValid('http://google'), 'https://google');
console.log('//////////////////////////////////////////////////////////////////');
```

#### isIPv4withTCPportValid

The `isIPv4withTCPportValid` function checks the IP address passed in the string for validity.

```js
console.log('Checking IP validity:');
console.log(nzfunc.isIPv4withTCPportValid('12.34.56.78:8000'), '12.34.56.78:8000');
console.log(nzfunc.isIPv4withTCPportValid('12.34.56.78'), '12.34.56.78');
```

#### doRequest and getResponse

`doRequest` and `getResponse` are asynchronous functions over http.

```js
(async () => {
	let obj = {
		request: 'sendMessage',
		message: 'Hello'
	};
	let options = {
		host: 127.0.0.1,
		port: 8080,
		path: '/',
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Content-Length': (JSON.stringify(obj)).length
		}
	};
	let req = await nzfunc.doRequest(options, JSON.stringify(obj));
	if (req.statusCode == 200) {
		let res = JSON.parse(await nzfunc.getResponse(req));
		console.log(res);
	}
})();
```


### License

[GNU Lesser General Public License](https://www.gnu.org/licenses/lgpl-3.0.en.html) (3.0 or any later version). Please take a look at the [LICENSE](LICENSE) file for more information.
