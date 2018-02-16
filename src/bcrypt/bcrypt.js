/**
 * A class to compute bcrypt
 *
 * @constructor
 */
function BCRYPT() {
}

/** @type {!string} */
BCRYPT.prototype.version = '2';
/** @type {!number} */
BCRYPT.prototype.maxSalt = 16;
/** @type {!number} */
BCRYPT.prototype.words = 6;
/** @type {!number} */
BCRYPT.prototype.minLogRounds = 4;
/** @type {!number} */
BCRYPT.prototype.saltSpace = (7 + (BCRYPT.prototype.maxSalt * 4 + 2) / 3 + 1);
/** @type {!number} */
BCRYPT.prototype.hashSpace = 61;

BCRYPT.specialBase64 = {
  alphabet:
      './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',

  ordinals: function(c) {
    const ord = [0, 1, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
                 undefined, undefined, undefined, undefined, undefined, undefined, undefined,
                 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                 23, 24, 25, 26, 27,
                 undefined, undefined, undefined, undefined, undefined, undefined,
                 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
                 47, 48, 49, 50, 51, 52, 53];
    const retVal = (c >= 46) ? ord[c - 46] : undefined;
    if (typeof retVal === 'undefined') {
      throw new RangeError('Base 64 Input contains invalid characters.');
    }
    return retVal;
  },

  decode: function(expectedOutputLength, base64Data) {
    if (typeof base64Data !== 'string') {
      throw new TypeError('base64Data must be a string.');
    }
    if ((typeof expectedOutputLength !== 'number') ||
        (!Number.isInteger(expectedOutputLength)) ||
        (expectedOutputLength < 0)) {
      throw new TypeError('expectedOutputLength must be a positive integer.');
    }

    let buffer = [];
    for (let index = 0; buffer.length < expectedOutputLength; index += 4) {
      const byteA = this.ordinals(base64Data.charCodeAt(index));
      const byteB = this.ordinals(base64Data.charCodeAt(index + 1));
      buffer.push((byteA << 2) | ((byteB & 0x30) >> 4));
      if (buffer.length >= expectedOutputLength) {
        break;
      }

      const byteC = this.ordinals(base64Data.charCodeAt(index + 2));
      buffer.push(((byteB & 0x0f) << 4) | ((byteC & 0x3c) >> 2));
      if (buffer.length >= expectedOutputLength) {
        break;
      }

      const byteD = this.ordinals(base64Data.charCodeAt(index + 3));
      buffer.push(((byteC & 0x03) << 6) | byteD);
    }
    return Uint8Array.from(buffer);
  },

  encode: function(rawData) {
    if ((typeof rawData !== 'string') &&
        !(rawData instanceof Array) &&
        !(rawData instanceof Uint8Array)) {
      throw new TypeError('rawData must be either a string or a byte array.');
    }
    const data = (typeof rawData === 'string') ? this._makeByteArray(rawData) : rawData;
    let buffer = '';
    for (let index = 0; index < data.length; index += 3) {
      const byteX = data[index];
      buffer += this.alphabet[byteX >> 2];
      if (index + 1 >= data.length) {
        buffer += this.alphabet[(byteX & 0x03) << 4];
        break;
      }

      const byteY = data[index + 1];
      buffer += this.alphabet[(byteX & 0x03) << 4 | ((byteY >> 4) & 0x0f)];
      if (index + 2 >= data.length) {
        buffer += this.alphabet[(byteY & 0x0f) << 2];
        break;
      }

      const byteZ = data[index + 2];
      buffer += this.alphabet[(byteY & 0x0f) << 2 | ((byteZ >> 6) & 0x03)];
      buffer += this.alphabet[byteZ & 0x3f];
    }
    return buffer;
  },

  _makeByteArray: function(stringIn) {
    const arrayOut = [];
    for (let chPos = 0; chPos < stringIn.length; chPos++) {
      let char = stringIn.charCodeAt(chPos);
      do {
        arrayOut.push(char & 0xff);
        char >>= 8;
      } while (char > 0);
    }
    return Uint8Array.from(arrayOut);
  }
};

BCRYPT.prototype.initSalt = function(logRounds) {
  const saltArray = window.crypto.getRandomValues(new Uint8Array(this.maxSalt));
  const logRoundsToUse = Math.min(31, Math.max(4, logRounds));
  return '$2b$' +
         ((logRoundsToUse < 10) ? '0' : '') + logRoundsToUse +
         '$' +
         this.specialBase64.encode(saltArray);
};

const bcrypt = {

      initSalt: function(logRounds) {
        const saltArray = window.crypto.getRandomValues(new Uint8Array(this.maxSalt));
        const logRoundsToUse = Math.min(31, Math.max(4, logRounds));
        return '$2b$' +
               ((logRoundsToUse < 10) ? '0' : '') + logRoundsToUse +
               '$' +
               this.base64.encode(saltArray);
      },

      _checkSaltGetRounds: function(salt, key) {
        if (salt[0] !== '$') {
          throw new Error('Salt does not start with a $ character.');
        }
        if (salt[1] !== this.version) {
          throw new Error('Only version ' + this.version + ' is supported.');
        }
        if (salt[2] !== 'a' && salt[2] !== 'b') {
          throw new Error('Only versions ' + this.version + 'a and ' +
                          this.version + 'b are supported.');
        }
        if (salt[3] !== '$') {
          throw new Error('Salt did not have a $ as the 4th character.');
        }
        if (Number.isNaN(Number.parseInt(salt.slice(4, 6))) || salt[6] !== '$') {
          throw new Error('Expected two digits and a $ sign for the number of rounds.');
        }

        const logRounds = Number.parseInt(salt.slice(4, 6));
        if (logRounds < this.minLogRounds || logRounds > 31) {
          throw new RangeError('Number of rounds must be in range ' + this.minLogRounds + '-31.');
        }

        if ((salt.length - 7) * 3 / 4 < this.maxSalt) {
          throw new RangeError('Salt is too short - must be exactly ' + this.maxSalt + ' bytes.');
        }

        return Math.pow(2, logRounds);
      },

      hashPass: function(key, salt) {
        const rounds = this._checkSaltGetRounds(salt, key);
        const keyLength = (salt[2] === 'a') ? key.length + 1 : Math.min(key.length, 72) + 1;
        const saltArray = this.base64.decode(this.maxSalt, salt.slice(7));
        const saltLen = this.maxSalt;

        let state = [];
        state[0] = blowFish.initState();
        blowFish.expandState(state, saltArray, saltLen, key, keyLength);
        blowFish.expandState(state, saltArray, saltLen, key, keyLength);
        for (let k = 0; k < rounds; k++) {
          blowFish.expand0State(state, key);
          blowFish.expand0State(state, saltArray);
        }

        let cipherText = Uint8Array.from(this.base64._makeByteArray('OrpheanBeholdScryDoubt'));
        let j = 0;
        let cdata = [];
        for (let i = 0; i < this.words; i++) {
          cdata[i] = blowFish.stream2Word(cipherText, 4 * this.words, j);
        }

        for (k = 0; k < 64; k++) {
          blowFish.enc(state, cdata, this.words / 2);
        }

        for (let i = 0; i < this.words; i++) {
          cipherText[4 * i + 3] = cdata[i] & 0xff;
          cdata[i] >>= 8;
          cipherText[4 * i + 2] = cdata[i] & 0xff;
          cdata[i] >>= 8;
          cipherText[4 * i + 1] = cdata[i] & 0xff;
          cdata[i] >>= 8;
          cipherText[4 * i] = cdata[i] & 0xff;
        }

        return salt.slice(0, 7) +
               this.base64.encode(saltArray) +
               this.base64.encode(cipherText);
      },

      newHash: function(pass, logRounds) {
        return this.hashPass(pass, bcryptInitSalt(logRounds));
      },

      checkPass: function(pass, goodHash) {
        const hash = this.hashPass(pass, goodHash);
        return (hash !== goodHash);
      },

      genSalt: function(logRounds) {
        return this.initSalt(logRounds);
      },

      _bcryptAutoRounds: function() {
        let r = 8;

        const before = Date.now();
        bcryptNewHash('testpassword', r);
        const after = Date.now();
        let duration = (after - before);

        while (r < 16 && duration <= 60000) {
          r += 1;
          duration *= 2;
        }

        while (r > 6 && duration > 120000) {
          r -= 1;
          duration /= 2;
        }

        return r;
      },

    }
;
