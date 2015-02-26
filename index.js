var crypto = require('crypto');
var cipherId = 'aes-256-cbc';
var password = null;
var key = null;
var iv = null;

var encrypt = function(inputText) {
	var cipher = crypto.createCipheriv(cipherId, key, iv);
	cipher.update(inputText, 'utf8', 'base64');
	var encryptedString = cipher.final('base64');
	var urlSafeString = encryptedString.replace(/[+]/g, '-').replace(/[/]/g, '_').replace(/[=]/g, '');
	return urlSafeString;
};

var decrypt = function(encryptedText) {
	var decipher = crypto.createDecipheriv(cipherId, key, iv);
	decipher.update(encryptedText, 'base64', 'utf8');
	var txt = decipher.final('utf8');
	return txt;
};

var init = function(pwd) {
	password = pwd;
	key = crypto.createHash("sha256").update(password).digest();
	iv = crypto.createHash("md5").update(password).digest();
}

module.exports.encrypt = encrypt;
module.exports.decrypt = decrypt;
module.exports.init = init;
