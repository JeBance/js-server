# nzfunc
[nzfunc](https://jebance.github.io/nzfunc/) is a function library.

**Table of Contents**

- [nzfunc](#nzfunc)
    - [Getting started](#getting-started)
        - [Node.js](#nodejs)
    - [Functions](#functions)
        - [hasJsonStructure](#hasJsonStructure)
    - [License](#license)


### nzfunc

* The nzfunc library is designed to minimize code and solve some application problems that do not have a standard solution in the JS language. The library will be expanded. You can suggest your function to be added to this module.

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


### License

[GNU Lesser General Public License](https://www.gnu.org/licenses/lgpl-3.0.en.html) (3.0 or any later version). Please take a look at the [LICENSE](LICENSE) file for more information.
