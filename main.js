const { BcryptHasher } = require('./BcryptHasher');

const hasher = new BcryptHasher();
const password = hasher.customPassword();
const hashedPassword = hasher.hashPassword(password);

console.log('Generated password: ' + password + '\n');
console.log('Hashed password: ' + hashedPassword + '\n');
console.log('Is it valid? ');
hasher.verifyHash(password, hashedPassword) ? console.log('Yes') : console.log('No');