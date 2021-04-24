const generatePassword = require('password-generator');
const bcrypt = require('bcrypt');


/**
 * clasa care genereaza o parola si o cripteaza folosind bcrypt
 */
class BcryptHasher {
    minLength = 12;
    maxLength = 18;
    uppercaseMinCount = 3;
    lowercaseMinCount = 3;
    numberMinCount = 2;
    specialMinCount = 2;
    UPPERCASE_RE = /([A-Z])/g;
    LOWERCASE_RE = /([a-z])/g;
    NUMBER_RE = /([\d])/g;
    SPECIAL_CHAR_RE = /([?\-])/g;
    NON_REPEATING_CHAR_RE = /([\w\d?\-])\1{2,}/g;

    constructor() {}

    /**
     * metoda care valideaza parola generata
     */
    isStrongEnough(password) {
        let uc = password.match(this.UPPERCASE_RE);
        let lc = password.match(this.LOWERCASE_RE);
        let n = password.match(this.NUMBER_RE);
        let sc = password.match(this.SPECIAL_CHAR_RE);
        let nr = password.match(this.NON_REPEATING_CHAR_RE);
        return password.length >= this.minLength &&
            !nr &&
            uc && uc.length >= this.uppercaseMinCount &&
            lc && lc.length >= this.lowercaseMinCount &&
            n && n.length >= this.numberMinCount &&
            sc && sc.length >= this.specialMinCount;
    }

    /**
     * metoda care genereaza o parola
     */
    customPassword() {
        let password = "";
        let randomLength = Math.floor(Math.random() * (this.maxLength - this.minLength)) + this.minLength;
        while (!this.isStrongEnough(password)) {
            password = generatePassword(randomLength, false, /[\w\d?\-]/);
        }
        return password;
    }

    /**
     * metoda care cripteaza o parola folosind bcrypt
     */
    hashPassword(password) {
        return bcrypt.hashSync(password, 10);
    }

    /**
     * metoda care verifica faptul ca parola a fost criptata cu succes
     */
    verifyHash(password, hash) {
        return bcrypt.compareSync(password, hash);
    }
}

module.exports = {BcryptHasher};