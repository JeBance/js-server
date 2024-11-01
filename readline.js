const process = require('process');
const readline = require('readline');
let config = {};

process.stdout.write('\x1Bc');

const rl = readline.createInterface(process.stdin, process.stdout);

	rl.question('Enter your name: ', data1 => {
		rl.question('Enter your e-mail: ', data2 => {
			rl.question('Enter password: ', data3 => {
				data1 = data1.split(' ');
				data2 = data2.split(' ');
				data3 = data3.split(' ');
				console.log(data1, data2, data3);
				rl.close();
			});
		});
	});

/*
const inputConfigData = ((prmtText) => {
	let rl = readline.createInterface({
		input: process.stdin,
		output: process.stdout,
		prompt: prmtText
	});
	rl.prompt();
	rl.on('line', (input) => {
		input = input.toLowerCase();
		console.log(input);
		rl.close();
	});
});
*/
/*
const questions = ((questionText) => {
	let {
    	stdin: input,
    	stdout: output,
	} = require('process');
	let rl = readline.createInterface({input, output});
	rl.question(questionText, (input) => {
		console.log(`Thank you for your valuable feedback: ${input}`);
		rl.close();
	});
	return input;
});

const getSomeQuestions = (async () => {
	let firstName = await questions('Enter your name: ');
	let email = await questions('Enter your e-mail: ');

});
*/



//	getSomeQuestions();
//	console.log('First name: ' + firstName);
/*
	let {
    	stdin: input,
    	stdout: output,
	} = require('process');
	let rl = readline.createInterface({input, output});
	rl.question('Enter your name: ', (input) => {
		console.log(`Thank you for your valuable feedback: ${input}`);
		rl.close();
	});
*/

/*
rl.on('line', line => {
	rl.question('Enter your name: ', (input) => {
		console.log(`Thank you for your valuable feedback: ${input}`);
//		rl.close();
	});

//    console.log(line);
}).on('close', () => {
     console.log('exit'); 
     process.exit(0);
});
*/











/*
(async () => {
    const message = await openpgp.createMessage({ text: 'Hello word! =)' });
    const encrypted = await openpgp.encrypt({
        message,
        passwords: ['secret_stuff'], // multiple passwords possible
        config: { preferredCompressionAlgorithm: openpgp.enums.compression.zlib } // compress the data with zlib
    });
    console.log(encrypted);
})();


require("readline").emitKeypressEvents(process.stdin);
process.stdin.setRawMode(true);

process.stdin.on("keypress", (char, evt) => {
  console.log("=====Key pressed=====");
  console.log("Char:", JSON.stringify(char), "Evt:", JSON.stringify(evt));

  if (char === "h") console.log("Hello World!");
  if (char === "q") process.exit();
});



const readline = require('readline');

const {
    stdin: input,
    stdout: output,
} = require('process');

const rl = readline.createInterface({ input, output });

rl.on('line', (input) => {
    if (input == 'exit') {
	console.log('\x1b[7m%s\x1b[0m',`Server shutdown`);
	process.exit(1);
    }
});



function uID()
{
	$mt = explode(' ', microtime());
	return $mt[1].substr($mt[0], 2, 6);
}

function uIDtoTime($uID = null)
{
	if (!empty($uID)) {
		return substr($uID, 0, 10);
		//return substr($uID, 10, 6);
	} else {
		return false;
	}
}

function getRandomKey()
{
	$length = 64;
	$characters = '0123456789AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz';
	$charactersLength = strlen($characters);
	$randomString = '';
	for ($i = 0; $i < $length; $i++) {
		$randomString .= $characters[rand(0, $charactersLength - 1)];
	}
	$randomString = hash_hmac('sha256', $randomString, uID());
	return $randomString;
}
*/
