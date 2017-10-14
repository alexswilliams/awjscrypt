// Inspired by the OpenBSD implementation

/**
 * Runs the entire MD5 algorithm for a single input (either a string or a byte array) and returns
 * a lower-case hex-encoded string with the digest in.
 *
 * @param {!Array<number>|!string|!Uint8Array} message
 * @return {!string}
 */
function md5(message) {
  md = new MD5();

  let messageToDigest;
  if (typeof message === 'string') {
    messageToDigest = md.makeByteArray(message);
  } else if (typeof message !== 'object') {
    throw new TypeError('Expected a Uint8Array or a string, but got a ' + typeof message);
  } else if (message instanceof Uint8Array) {
    messageToDigest = message;
  } else {
    throw new TypeError('Expected a Uint8Array or a string, but got a ' +
                        message.constructor.name);
  }

  md.update(messageToDigest, messageToDigest.length);
  return md.makeHexString(md.final());
}

/**
 * A class that can compute MD5.
 *
 * @constructor
 */
function MD5() {
  this.init();
}

/** @type {!number} */
MD5.prototype.MD5_BLOCK_LENGTH = 64;
/** @type {!number} */
MD5.prototype.MD5_DIGEST_LENGTH = 16;
/** @type {!number} */
MD5.prototype.MD5_DIGEST_STRING_LENGTH = (MD5.prototype.MD5_DIGEST_LENGTH * 2 + 1);

/**
 * Converts a 64-bit number to its individual bytes and stores them into a byte array.
 * THIS DOESN'T WORK FOR NUMBERS THAT USE MORE THAN 56 BITS because javascript.
 * As a result, I chose to clamp this to 32 bit numbers.
 *
 * @param {!Uint8Array} cp
 * @param {!number} value
 */
MD5.prototype.put64LittleEndian = function(cp, value) {
  cp[7] = 0; //(value >>> 56) & 0xff;
  cp[6] = 0; //(value >>> 48) & 0xff;
  cp[5] = 0; //(value >>> 40) & 0xff;
  cp[4] = 0; //(value >>> 32) & 0xff;
  cp[3] = (value >>> 24) & 0xff;
  cp[2] = (value >>> 16) & 0xff;
  cp[1] = (value >>> 8) & 0xff;
  cp[0] = (value) & 0xff;
};

/**
 * Converts a 32-bit number to its individual bytes and stores them into a byte array.
 *
 * @param {!Uint8Array} cp
 * @param {!number} offset
 * @param {!number} value
 */
MD5.prototype.put32LittleEndian = function(cp, offset, value) {
  cp[3 + offset] = (value >>> 24) & 0xff;
  cp[2 + offset] = (value >>> 16) & 0xff;
  cp[1 + offset] = (value >>> 8) & 0xff;
  cp[0 + offset] = (value) & 0xff;
};

/** @type {!Uint8Array} */
MD5.prototype.PADDING = Uint8Array.from(
    [
      0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    ]);

/**
 * @typedef {[!number,!number,!number,!number]} MD5State
 * @typedef {{count: !number, state: !MD5State, buffer: !Uint8Array}} MD5Context
 */

/**
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
MD5.prototype.init = function() {
  /**
   * @type MD5Context
   */
  this.context = {
    count: 0,
    state: [
      0x67452301,
      0xefcdab89,
      0x98badcfe,
      0x10325476
    ],
    buffer: new Uint8Array(this.MD5_BLOCK_LENGTH)
  };
};

/**
 * Update context to reflect the concatenation of another buffer full of bytes.
 *
 * @param {!Uint8Array} input Byte array to digest
 * @param {!Number} len       Number of bytes contained in input.
 */
MD5.prototype.update = function(input, len) {
  // Check how many bytes we already have and how many more we need
  // in order to fill the current block.

  /** @type {number} */
  let have = (this.context.count / 8) & (this.MD5_BLOCK_LENGTH - 1);
  /** @type {number} */
  let need = this.MD5_BLOCK_LENGTH - have;

  // Update bitcount
  this.context.count += len * 8;

  let inputOffset = 0;
  let bytesRemaining = len;

  // If adding this new input to the buffer would overflow the buffer, then process it.
  if (bytesRemaining >= need) {
    if (have !== 0) {
      this.byteArrayCopy(this.context.buffer, have, input, inputOffset, need);
      this.transform();
      inputOffset += need;
      bytesRemaining -= need;
      have = 0;
    }

    // Process data in MD5_BLOCK_LEN-byte chunks.
    while (bytesRemaining >= this.MD5_BLOCK_LENGTH) {
      this.byteArrayCopy(this.context.buffer, 0, input, inputOffset, this.MD5_BLOCK_LENGTH);
      this.transform();
      inputOffset += this.MD5_BLOCK_LENGTH;
      bytesRemaining -= this.MD5_BLOCK_LENGTH;
    }
  }

  // Handle any remaining bytes of data.
  // These bytes go into the buffer ready to be transformed next time.
  if (bytesRemaining !== 0) {
    this.byteArrayCopy(this.context.buffer, have, input, inputOffset, bytesRemaining);
  }

};

/**
 * Copies from input to buffer
 *
 * @param {!Uint8Array} buffer
 * @param {!number} bufferOffset
 * @param {!Uint8Array} input
 * @param {!number} inputOffset
 * @param {!number} inputLength
 */
MD5.prototype.byteArrayCopy = function(buffer, bufferOffset, input, inputOffset, inputLength) {
  for (let i = 0; i < inputLength; i++) {
    buffer[bufferOffset + i] = input[inputOffset + i];
  }
};

/**
 * Pad pad to 64-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
MD5.prototype.pad = function() {
  let countArray = new Uint8Array(8);

  // Convert count to 8 bytes in little endian order.
  this.put64LittleEndian(countArray, this.context.count);

  // Pad out to 56 mod 64 (leaves 8 bytes spare for the 64-bit bitlength.
  let padlen = this.MD5_BLOCK_LENGTH -
               ((this.context.count / 8) & (this.MD5_BLOCK_LENGTH - 1));

  if (padlen < (1 + 8)) {
    padlen += this.MD5_BLOCK_LENGTH;
  }

  this.update(this.PADDING, padlen - 8); // padlen - 8 <= 64
  this.update(countArray, 8);
};

/**
 * Final wrapup--call MD5Pad, fill in digest and zero out ctx.
 * @return {Uint8Array}
 */
MD5.prototype.final = function() {
  let digest = new Uint8Array(this.MD5_DIGEST_LENGTH);
  console.log(this.context.state, this.context.buffer);
  this.pad();
  console.log(this.context.count, this.context.state, this.context.buffer);

  for (let i = 0; i < 4; i++) {
    this.put32LittleEndian(digest, i * 4, this.context.state[i]);
    console.log(digest);
  }
  this.explicitZero();
  this.init();
  return digest;
};

MD5.prototype.explicitZero = function() {
  this.context.count = 0;
  this.context.state[0] = 0;
  this.context.state[1] = 0;
  this.context.state[2] = 0;
  this.context.state[3] = 0;
  for (let i = 0; i < 64; i++) {
    this.context.buffer[i] = 0;
  }
};

MD5.prototype.f1 = function(x, y, z) {
  return (z ^ (x & (y ^ z)));
};

MD5.prototype.f2 = function(x, y, z) {
  return MD5.prototype.f1(z, x, y);
};

MD5.prototype.f3 = function(x, y, z) {
  return (x ^ y ^ z);
};

MD5.prototype.f4 = function(x, y, z) {
  return (y ^ (x | ~z));
};

/**
 *
 * @param {!function<!number,!number,!number>} f
 * @param {!number} w
 * @param {!number} x
 * @param {!number} y
 * @param {!number} z
 * @param {!number} data
 * @param {!number} s
 * @return {!number}
 */
MD5.prototype.step = function(f, w, x, y, z, data, s) {
  let t = w + f(x, y, z) + data;
  t = (t << s) | (t >>> (32 - s));
  t += x;
  return t & 0xffffffff;
};

MD5.prototype.bufferToDwordArray = function() {
  const intArray = new Uint32Array(this.MD5_BLOCK_LENGTH / 4);
  for (let a = 0; a < this.MD5_BLOCK_LENGTH / 4; a++) {
    intArray[a] = (this.context.buffer[a * 4]) |
                  ((this.context.buffer[a * 4 + 1]) << 8) |
                  ((this.context.buffer[a * 4 + 2]) << 16) |
                  ((this.context.buffer[a * 4 + 3]) << 24);
  }
  return intArray;
};

/**
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5.Update blocks
 * the data and converts bytes into longwords for this routine.
 */
MD5.prototype.transform = function() {
  const bufferAsDwords = this.bufferToDwordArray();

  console.log('TRANSFORM');

  let a = this.context.state[0];
  let b = this.context.state[1];
  let c = this.context.state[2];
  let d = this.context.state[3];

  a = this.step(this.f1, a, b, c, d, bufferAsDwords[0] + 0xd76aa478, 7);
  d = this.step(this.f1, d, a, b, c, bufferAsDwords[1] + 0xe8c7b756, 12);
  c = this.step(this.f1, c, d, a, b, bufferAsDwords[2] + 0x242070db, 17);
  b = this.step(this.f1, b, c, d, a, bufferAsDwords[3] + 0xc1bdceee, 22);
  a = this.step(this.f1, a, b, c, d, bufferAsDwords[4] + 0xf57c0faf, 7);
  d = this.step(this.f1, d, a, b, c, bufferAsDwords[5] + 0x4787c62a, 12);
  c = this.step(this.f1, c, d, a, b, bufferAsDwords[6] + 0xa8304613, 17);
  b = this.step(this.f1, b, c, d, a, bufferAsDwords[7] + 0xfd469501, 22);
  a = this.step(this.f1, a, b, c, d, bufferAsDwords[8] + 0x698098d8, 7);
  d = this.step(this.f1, d, a, b, c, bufferAsDwords[9] + 0x8b44f7af, 12);
  c = this.step(this.f1, c, d, a, b, bufferAsDwords[10] + 0xffff5bb1, 17);
  b = this.step(this.f1, b, c, d, a, bufferAsDwords[11] + 0x895cd7be, 22);
  a = this.step(this.f1, a, b, c, d, bufferAsDwords[12] + 0x6b901122, 7);
  d = this.step(this.f1, d, a, b, c, bufferAsDwords[13] + 0xfd987193, 12);
  c = this.step(this.f1, c, d, a, b, bufferAsDwords[14] + 0xa679438e, 17);
  b = this.step(this.f1, b, c, d, a, bufferAsDwords[15] + 0x49b40821, 22);

  a = this.step(this.f2, a, b, c, d, bufferAsDwords[1] + 0xf61e2562, 5);
  d = this.step(this.f2, d, a, b, c, bufferAsDwords[6] + 0xc040b340, 9);
  c = this.step(this.f2, c, d, a, b, bufferAsDwords[11] + 0x265e5a51, 14);
  b = this.step(this.f2, b, c, d, a, bufferAsDwords[0] + 0xe9b6c7aa, 20);
  a = this.step(this.f2, a, b, c, d, bufferAsDwords[5] + 0xd62f105d, 5);
  d = this.step(this.f2, d, a, b, c, bufferAsDwords[10] + 0x02441453, 9);
  c = this.step(this.f2, c, d, a, b, bufferAsDwords[15] + 0xd8a1e681, 14);
  b = this.step(this.f2, b, c, d, a, bufferAsDwords[4] + 0xe7d3fbc8, 20);
  a = this.step(this.f2, a, b, c, d, bufferAsDwords[9] + 0x21e1cde6, 5);
  d = this.step(this.f2, d, a, b, c, bufferAsDwords[14] + 0xc33707d6, 9);
  c = this.step(this.f2, c, d, a, b, bufferAsDwords[3] + 0xf4d50d87, 14);
  b = this.step(this.f2, b, c, d, a, bufferAsDwords[8] + 0x455a14ed, 20);
  a = this.step(this.f2, a, b, c, d, bufferAsDwords[13] + 0xa9e3e905, 5);
  d = this.step(this.f2, d, a, b, c, bufferAsDwords[2] + 0xfcefa3f8, 9);
  c = this.step(this.f2, c, d, a, b, bufferAsDwords[7] + 0x676f02d9, 14);
  b = this.step(this.f2, b, c, d, a, bufferAsDwords[12] + 0x8d2a4c8a, 20);

  a = this.step(this.f3, a, b, c, d, bufferAsDwords[5] + 0xfffa3942, 4);
  d = this.step(this.f3, d, a, b, c, bufferAsDwords[8] + 0x8771f681, 11);
  c = this.step(this.f3, c, d, a, b, bufferAsDwords[11] + 0x6d9d6122, 16);
  b = this.step(this.f3, b, c, d, a, bufferAsDwords[14] + 0xfde5380c, 23);
  a = this.step(this.f3, a, b, c, d, bufferAsDwords[1] + 0xa4beea44, 4);
  d = this.step(this.f3, d, a, b, c, bufferAsDwords[4] + 0x4bdecfa9, 11);
  c = this.step(this.f3, c, d, a, b, bufferAsDwords[7] + 0xf6bb4b60, 16);
  b = this.step(this.f3, b, c, d, a, bufferAsDwords[10] + 0xbebfbc70, 23);
  a = this.step(this.f3, a, b, c, d, bufferAsDwords[13] + 0x289b7ec6, 4);
  d = this.step(this.f3, d, a, b, c, bufferAsDwords[0] + 0xeaa127fa, 11);
  c = this.step(this.f3, c, d, a, b, bufferAsDwords[3] + 0xd4ef3085, 16);
  b = this.step(this.f3, b, c, d, a, bufferAsDwords[6] + 0x04881d05, 23);
  a = this.step(this.f3, a, b, c, d, bufferAsDwords[9] + 0xd9d4d039, 4);
  d = this.step(this.f3, d, a, b, c, bufferAsDwords[12] + 0xe6db99e5, 11);
  c = this.step(this.f3, c, d, a, b, bufferAsDwords[15] + 0x1fa27cf8, 16);
  b = this.step(this.f3, b, c, d, a, bufferAsDwords[2] + 0xc4ac5665, 23);

  a = this.step(this.f4, a, b, c, d, bufferAsDwords[0] + 0xf4292244, 6);
  d = this.step(this.f4, d, a, b, c, bufferAsDwords[7] + 0x432aff97, 10);
  c = this.step(this.f4, c, d, a, b, bufferAsDwords[14] + 0xab9423a7, 15);
  b = this.step(this.f4, b, c, d, a, bufferAsDwords[5] + 0xfc93a039, 21);
  a = this.step(this.f4, a, b, c, d, bufferAsDwords[12] + 0x655b59c3, 6);
  d = this.step(this.f4, d, a, b, c, bufferAsDwords[3] + 0x8f0ccc92, 10);
  c = this.step(this.f4, c, d, a, b, bufferAsDwords[10] + 0xffeff47d, 15);
  b = this.step(this.f4, b, c, d, a, bufferAsDwords[1] + 0x85845dd1, 21);
  a = this.step(this.f4, a, b, c, d, bufferAsDwords[8] + 0x6fa87e4f, 6);
  d = this.step(this.f4, d, a, b, c, bufferAsDwords[15] + 0xfe2ce6e0, 10);
  c = this.step(this.f4, c, d, a, b, bufferAsDwords[6] + 0xa3014314, 15);
  b = this.step(this.f4, b, c, d, a, bufferAsDwords[13] + 0x4e0811a1, 21);
  a = this.step(this.f4, a, b, c, d, bufferAsDwords[4] + 0xf7537e82, 6);
  d = this.step(this.f4, d, a, b, c, bufferAsDwords[11] + 0xbd3af235, 10);
  c = this.step(this.f4, c, d, a, b, bufferAsDwords[2] + 0x2ad7d2bb, 15);
  b = this.step(this.f4, b, c, d, a, bufferAsDwords[9] + 0xeb86d391, 21);

  this.context.state[0] += a;
  this.context.state[1] += b;
  this.context.state[2] += c;
  this.context.state[3] += d;
};

/**
 * @param {string} stringIn
 * @return {Uint8Array}
 */
MD5.prototype.makeByteArray = function(stringIn) {
  const arrayOut = [];
  for (let chPos = 0; chPos < stringIn.length; chPos++) {
    let char = stringIn.charCodeAt(chPos);
    do {
      arrayOut.push(char & 0xff);
      char >>= 8;
    } while (char > 0);
  }
  return Uint8Array.from(arrayOut);
};

/**
 * @param {Uint8Array} byteArrayIn
 * @return {string}
 */
MD5.prototype.makeHexString = function(byteArrayIn) {
  let stringOut = '';
  const hexArray = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];
  for (let i = 0; i < byteArrayIn.length; i++) {
    const hi = byteArrayIn[i] >> 4 & 0x0f;
    const lo = byteArrayIn[i] & 0x0f;
    stringOut += hexArray[hi] + hexArray[lo];
  }
  return stringOut;
};

/**
 * @param {number} dword
 * @param {boolean} [prefix]
 * @return {string}
 */
MD5.prototype.dwordToHex = function(dword, prefix = true) {
  const hexArray = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];

  n8 = (dword >> 28) & 0x0f;
  n7 = (dword >> 24) & 0x0f;
  n6 = (dword >> 20) & 0x0f;
  n5 = (dword >> 16) & 0x0f;
  n4 = (dword >> 12) & 0x0f;
  n3 = (dword >> 8) & 0x0f;
  n2 = (dword >> 4) & 0x0f;
  n1 = (dword >> 0) & 0x0f;

  return ((prefix) ? '0x' : '') +
         '' +
         hexArray[n8] + hexArray[n7] + hexArray[n6] + hexArray[n5] +
         hexArray[n4] + hexArray[n3] + hexArray[n2] + hexArray[n1];
};
