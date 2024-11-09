# nzfsdb
[nzfsdb](https://jebance.github.io/nzfsdb/) is a library nosql database.

**Table of Contents**

- [nzfsdb](#nzfsdb)
    - [Getting started](#getting-started)
        - [Node.js](#nodejs)
    - [Example](#example)
    - [License](#license)


### nzfsdb

* nzfsdb allows you to create nosql databases in the file system.

* The `index.js` bundle works well in Node.js. It is used by default when you `require('nzfsdb')` in Node.js.


### Getting started

#### Node.js

Install nzfsdb using npm:

```sh
npm install nzfsdb
```

And import it as a CommonJS module:

```js
const nzfsdb = require('nzfsdb');
```


### Example

Here is an example of using this class in a project.

```js
const nzfsdb = require('nzfsdb');

const DB = new nzfsdb(__dirname + '/DB/');

console.log('1. Checking the database root folder:\n', DB.checkExists(), '\n');
console.log('2. Checking the "pub" folder of the database:\n', DB.checkExists('pub'), '\n');
console.log('3. Checking file "123.txt" in folder "pub":\n', DB.checkExists('pub', '123.txt'), '\n');
console.log('4. Reading the list of files in the "pub" folder:\n', DB.read('pub'), '\n');
console.log('5. Writing file "12345.txt" to folder "pub" with content "test":', DB.write('pub/some/dir', '12345.txt', 'test'), '\n');	// comment this line later
console.log('6. Reading file "12345.txt" in folder "pub":', DB.read('pub/some/dir', '12345.txt'), '\n');
console.log('7. Deleting file "12345.txt" in folder "pub":', DB.delete('pub/some/dir', '12345.txt'), '\n');
console.log('8. Deleting the "some" folder and all its data:', DB.delete('pub/some'), '\n');
```


### License

[GNU Lesser General Public License](https://www.gnu.org/licenses/lgpl-3.0.en.html) (3.0 or any later version). Please take a look at the [LICENSE](LICENSE) file for more information.
