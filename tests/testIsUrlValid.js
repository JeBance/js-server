const process = require('process');
const nzfunc = require('nzfunc');

process.stdout.write('\x1Bc');

console.log('Checking URL validity:');
console.log('TRUE /////////////////////////////////////////////////////////////');
console.log(nzfunc.isIPv4withTCPportValid('12.34.56.78:8000'), '12.34.56.78:8000');
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
console.log(nzfunc.isIPv4withTCPportValid('12.34.56.78'), '12.34.56.78');
console.log(nzfunc.isUrlValid('tg://t.me'), 'tg://t.me');
console.log(nzfunc.isUrlValid('http://google'), 'https://google');
console.log('//////////////////////////////////////////////////////////////////');

