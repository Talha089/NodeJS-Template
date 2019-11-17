'use strict';
                                        // Logger

let logger = require("../logger");
let config = require('../config/environment');

logger.info('encryption util file loaded');

                                // Nodejs encryption with CTR

let crypto = require('crypto'), algorithm = 'aes-256-ecb', password = config.encPass;

exports.encryptdata = (text)=>
{
                            // text = JSON.stringify(text);
                            
	let cipher = crypto.createCipher(algorithm,password,null);

	let crypted = cipher.update(text,'utf8','hex')
	crypted += cipher.final('hex');
	return crypted;		
}
 
exports.decryptdata = (text)=>
{
	  let decipher = crypto.createDecipher(algorithm,password,null)
	  let dec = decipher.update(text,'hex','utf8')
	  dec += decipher.final('utf8');
	  return dec;
}