const process = require('process');
const nzfsdb = require('./index.js');

process.stdout.write('\x1Bc');

const DB = new nzfsdb(__dirname + '/DB/');

console.log('1. Checking the database root folder:\n', DB.checkExists(), '\n');
console.log('2. Checking the "pub" folder of the database:\n', DB.checkExists('pub'), '\n');
console.log('3. Checking file "123.txt" in folder "pub":\n', DB.checkExists('pub', '123.txt'), '\n');
console.log('4. Reading the list of files in the "pub" folder:\n', DB.read('pub'), '\n');
console.log('5. Writing file "12345.txt" to folder "pub" with content "test":', DB.write('pub/some/dir', '12345.txt', 'test'), '\n');	// comment this line later
console.log('6. Reading file "12345.txt" in folder "pub":', DB.read('pub/some/dir', '12345.txt'), '\n');
console.log('7. Deleting file "12345.txt" in folder "pub":', DB.delete('pub/some/dir', '12345.txt'), '\n');
console.log('8. Deleting the "some" folder and all its data:', DB.delete('pub/some'), '\n');
