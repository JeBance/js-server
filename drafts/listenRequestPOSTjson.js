			if (request.hasOwnProperty('request') === true) {
				if (request.request.method == 'handshake') {
					if (request.request.hasOwnProperty('fingerprint') === true) {
						if (request.request.hasOwnProperty('publicKey') === true) {
							
							res.writeHead(200);
							res.end(JSON.stringify({result:'Data successfully received'}));
						} else {
							res.writeHead(500);
							res.end(JSON.stringify({error:'Invalid request: "Public key missing"'}));
						}
					} else {
						res.writeHead(500);
						res.end(JSON.stringify({error:'Invalid request: "Missing fingerprint"'}));
					}

				} else if (request.request.method == 'sendMessage') {
					if (request.request.hasOwnProperty('to') === true) {
						if (request.request.hasOwnProperty('message') === true) {
							// проверяем сообщение
							if ((await sPGPs.checkMessage(request.request.message)) === true) {
								const senderPublicKeyArmored = sPGPs.publicKeyArmored;
								let decrypted = await sPGPs.decryptMessage(request.request.message, senderPublicKeyArmored);
								console.log('Decrypted message:');
								console.log(decrypted);
							}

							res.writeHead(200);
							res.end(JSON.stringify({result:'Data successfully received'}));
						} else {
							res.writeHead(500);
							res.end(JSON.stringify({error:'Invalid request: "Message missing"'}));
						}
					} else {
						res.writeHead(500);
						res.end(JSON.stringify({error:'Invalid request: "Recipient not specified"'}));
					}

				} else if (request.request.method == 'getNewMessage') {
					// проверяем подпись клиента и отдаём его сообщения
					res.writeHead(200);
					res.end(JSON.stringify({result:'Data successfully received'}));
				} else if (request.request.method == 'deleteMessage') {
					if (request.hasOwnProperty('messages') === true) {
						// проверяем подпись клиента и удаляем массив сообщений
						// отправляем сообщение пяти нодам
					} else {
						res.writeHead(500);
						res.end(JSON.stringify({error:'Invalid request'}));
					}
				} else {
					res.writeHead(500);
					res.end(JSON.stringify({error:'Invalid request: "Unknown method"'}));
				}

			} else {
				res.writeHead(500);
				res.end(JSON.stringify({error:'Invalid request: "One of the parameters is missing: request or signature"'}));
			}

