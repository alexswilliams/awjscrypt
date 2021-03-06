
const md5Tests = [
  // Testing MD5::init
  {
    desc: 'A new MD5() object has a context object with the right type',
    testFunction: function() {
      let mdEncoder = new MD5();
      return typeof mdEncoder.context;
    },
    expectedResult: 'object'
  },
  {
    desc: 'A new MD5() object has a context with a count which is the number 0',
    testFunction: function() {
      let mdEncoder = new MD5();
      return mdEncoder.context.count;
    },
    expectedResult: 0
  },
  {
    desc: 'A new MD5() object has a context with a state which is an array',
    testFunction: function() {
      let mdEncoder = new MD5();
      return mdEncoder.context.state.constructor.name;
    },
    expectedResult: 'Array'
  },
  {
    desc: 'A new MD5() object has a context with a state which has 4 elements',
    testFunction: function() {
      let mdEncoder = new MD5();
      return mdEncoder.context.state.length;
    },
    expectedResult: 4
  },
  {
    desc: 'A new MD5() object has a context with a state with a correct elements',
    testFunction: function(input) {
      let mdEncoder = new MD5();
      return mdEncoder.context.state[input[0]];
    },
    dataProvider: [
      {input: [0], expectedOutput: 0x67452301},
      {input: [1], expectedOutput: 0xefcdab89},
      {input: [2], expectedOutput: 0x98badcfe},
      {input: [3], expectedOutput: 0x10325476},
    ]
  },
  {
    desc: 'A new MD5() object has a context with a buffer which is a typed 8-bit array',
    testFunction: function() {
      let mdEncoder = new MD5();
      return mdEncoder.context.buffer.constructor.name;
    },
    expectedResult: 'Uint8Array'
  },
  {
    desc: 'A new MD5() object has a context with a buffer which has 64 elements',
    testFunction: function() {
      let mdEncoder = new MD5();
      return mdEncoder.context.buffer.length;
    },
    expectedResult: 64
  },

  // Testing MD5::update
  {
    desc: 'A single update from an empty state with a block shorter than the MD5 block ' +
          'length should call transform 0 times.',
    testFunction: function() {
      let mdEncoder = new MD5();
      mdEncoder.transformCallCount = 0;
      mdEncoder.transform = function(block) {
        this.transformCallCount++;
      };

      let blockA = new Uint8Array(mdEncoder.MD5_BLOCK_LENGTH - 1);
      mdEncoder.update(blockA, mdEncoder.MD5_BLOCK_LENGTH - 1);

      return mdEncoder.transformCallCount;
    },
    expectedResult: 0
  },
  {
    desc: 'Two calls to update from an empty state with two blocks both shorter than ' +
          'half the MD5 block length should call transform 0 times.',
    testFunction: function() {
      let mdEncoder = new MD5();
      mdEncoder.transformCallCount = 0;
      mdEncoder.transform = function(block) {
        this.transformCallCount++;
      };

      let blockA = new Uint8Array(mdEncoder.MD5_BLOCK_LENGTH / 2 - 1);
      let blockB = new Uint8Array(mdEncoder.MD5_BLOCK_LENGTH / 2 - 1);
      mdEncoder.update(blockA, mdEncoder.MD5_BLOCK_LENGTH / 2 - 1);
      mdEncoder.update(blockB, mdEncoder.MD5_BLOCK_LENGTH / 2 - 1);

      return mdEncoder.transformCallCount;
    },
    expectedResult: 0
  },
  {
    desc: 'A single update from an empty state with a block equal length to the MD5 ' +
          'block length should call transform 1 time.',
    testFunction: function() {
      let mdEncoder = new MD5();
      mdEncoder.transformCallCount = 0;
      mdEncoder.transform = function(block) {
        this.transformCallCount++;
      };

      let blockA = new Uint8Array(mdEncoder.MD5_BLOCK_LENGTH);
      mdEncoder.update(blockA, mdEncoder.MD5_BLOCK_LENGTH);

      return mdEncoder.transformCallCount;
    },
    expectedResult: 1
  },
  {
    desc: 'A single update from an empty state with a block length between 1 and 2 times ' +
          'the MD5 block length should call transform 1 time.',
    testFunction: function() {
      let mdEncoder = new MD5();
      mdEncoder.transformCallCount = 0;
      mdEncoder.transform = function(block) {
        this.transformCallCount++;
      };

      let blockA = new Uint8Array(mdEncoder.MD5_BLOCK_LENGTH * 1.5);
      mdEncoder.update(blockA, mdEncoder.MD5_BLOCK_LENGTH * 1.5);

      return mdEncoder.transformCallCount;
    },
    expectedResult: 1
  },
  {
    desc: 'Two calls to update from an empty state such that the second block will ' +
          'overflow the MD5 block length should call transform 1 time.',
    testFunction: function() {
      let mdEncoder = new MD5();
      mdEncoder.transformCallCount = 0;
      mdEncoder.transform = function(block) {
        this.transformCallCount++;
      };

      let blockA = new Uint8Array(mdEncoder.MD5_BLOCK_LENGTH - 1);
      let blockB = new Uint8Array(mdEncoder.MD5_BLOCK_LENGTH - 1);
      mdEncoder.update(blockA, mdEncoder.MD5_BLOCK_LENGTH - 1);
      mdEncoder.update(blockB, mdEncoder.MD5_BLOCK_LENGTH - 1);

      return mdEncoder.transformCallCount;
    },
    expectedResult: 1
  },
  {
    desc: 'Two calls to update from an empty state such that both blocks will ' +
          'overflow the MD5 block length should call transform 2 time.',
    testFunction: function() {
      let mdEncoder = new MD5();
      mdEncoder.transformCallCount = 0;
      mdEncoder.transform = function(block) {
        this.transformCallCount++;
      };

      let blockA = new Uint8Array(mdEncoder.MD5_BLOCK_LENGTH + 1);
      let blockB = new Uint8Array(mdEncoder.MD5_BLOCK_LENGTH + 1);
      mdEncoder.update(blockA, mdEncoder.MD5_BLOCK_LENGTH + 1);
      mdEncoder.update(blockB, mdEncoder.MD5_BLOCK_LENGTH + 1);

      return mdEncoder.transformCallCount;
    },
    expectedResult: 2
  },
  {
    desc: 'Calling update with a 0-length input will not change the bit counter.',
    testFunction: function() {
      let mdEncoder = new MD5();
      let blockA = new Uint8Array(2);

      let countBefore = mdEncoder.context.count;
      mdEncoder.update(blockA, 0);
      let countAfter = mdEncoder.context.count;

      return (countBefore === countAfter);
    },
    expectedResult: true
  },
  {
    desc: 'Calling update from new context with an input less than the block length will ' +
          'add the input length (in bits) to the bit counter.',
    testFunction: function() {
      let mdEncoder = new MD5();
      let blockA = new Uint8Array(mdEncoder.MD5_BLOCK_LENGTH - 1);

      let countBefore = mdEncoder.context.count;
      mdEncoder.update(blockA, mdEncoder.MD5_BLOCK_LENGTH - 1);
      return mdEncoder.context.count - countBefore;
    },
    expectedResult: (64 - 1) * 8
  },
  {
    desc: 'Calling update from new context with an input more than the block length will ' +
          'add the input length (in bits) to the bit counter.',
    testFunction: function() {
      let mdEncoder = new MD5();
      let blockA = new Uint8Array(mdEncoder.MD5_BLOCK_LENGTH + 1);

      let countBefore = mdEncoder.context.count;
      mdEncoder.update(blockA, mdEncoder.MD5_BLOCK_LENGTH + 1);
      return mdEncoder.context.count - countBefore;
    },
    expectedResult: (64 + 1) * 8
  },
  {
    desc: 'Calling update from a part-filled context with an input that will overflow ' +
          'the block length will add the input length (in bits) to the bit counter.',
    testFunction: function() {
      let mdEncoder = new MD5();
      let blockA = new Uint8Array(mdEncoder.MD5_BLOCK_LENGTH - 1);
      mdEncoder.update(blockA, mdEncoder.MD5_BLOCK_LENGTH - 1);

      let countBefore = mdEncoder.context.count;
      mdEncoder.update(blockA, mdEncoder.MD5_BLOCK_LENGTH - 1);
      return mdEncoder.context.count - countBefore;
    },
    expectedResult: (64 - 1) * 8
  },
  {
    desc: 'Calling update from a new context with an input that will overflow ' +
          'the block length will leave the remaining bytes (extra to the block length) ' +
          'at the start of the buffer.',
    testFunction: function() {
      let mdEncoder = new MD5();
      let blockA = new Uint8Array(mdEncoder.MD5_BLOCK_LENGTH + 2);
      blockA[mdEncoder.MD5_BLOCK_LENGTH] = 22;
      blockA[mdEncoder.MD5_BLOCK_LENGTH + 1] = 33;

      mdEncoder.update(blockA, mdEncoder.MD5_BLOCK_LENGTH + 2);

      return mdEncoder.context.buffer[0] + '/' + mdEncoder.context.buffer[1];
    },
    expectedResult: '22/33'
  },

  {
    desc: 'All sample F1 inputs produce the expected output.',
    dataProvider: [
      {input: [0x2c8a718a, 0x6abca475, 0x397fbaee], expectedOutput: '0x39fdaa64'},
      {input: [0x00000000, 0x00000000, 0x00000000], expectedOutput: '0x00000000'},
      {input: [0x00000000, 0x00000000, 0x2648ace0], expectedOutput: '0x2648ace0'},
      {input: [0x00000000, 0x00000000, 0xffffffff], expectedOutput: '0xffffffff'},
      {input: [0x00000000, 0x87654321, 0x00000000], expectedOutput: '0x00000000'},
      {input: [0x00000000, 0x87654321, 0x2648ace0], expectedOutput: '0x2648ace0'},
      {input: [0x00000000, 0x87654321, 0xffffffff], expectedOutput: '0xffffffff'},
      {input: [0x00000000, 0xffffffff, 0x00000000], expectedOutput: '0x00000000'},
      {input: [0x00000000, 0xffffffff, 0x2648ace0], expectedOutput: '0x2648ace0'},
      {input: [0x00000000, 0xffffffff, 0xffffffff], expectedOutput: '0xffffffff'},
      {input: [0x12345678, 0x00000000, 0x00000000], expectedOutput: '0x00000000'},
      {input: [0x12345678, 0x00000000, 0x2648ace0], expectedOutput: '0x2448a880'},
      {input: [0x12345678, 0x00000000, 0xffffffff], expectedOutput: '0xedcba987'},
      {input: [0x12345678, 0x87654321, 0x00000000], expectedOutput: '0x02244220'},
      {input: [0x12345678, 0x87654321, 0x2648ace0], expectedOutput: '0x266ceaa0'},
      {input: [0x12345678, 0x87654321, 0xffffffff], expectedOutput: '0xefefeba7'},
      {input: [0x12345678, 0xffffffff, 0x00000000], expectedOutput: '0x12345678'},
      {input: [0x12345678, 0xffffffff, 0x2648ace0], expectedOutput: '0x367cfef8'},
      {input: [0x12345678, 0xffffffff, 0xffffffff], expectedOutput: '0xffffffff'},
      {input: [0xffffffff, 0x00000000, 0x00000000], expectedOutput: '0x00000000'},
      {input: [0xffffffff, 0x00000000, 0x2648ace0], expectedOutput: '0x00000000'},
      {input: [0xffffffff, 0x00000000, 0xffffffff], expectedOutput: '0x00000000'},
      {input: [0xffffffff, 0x87654321, 0x00000000], expectedOutput: '0x87654321'},
      {input: [0xffffffff, 0x87654321, 0x2648ace0], expectedOutput: '0x87654321'},
      {input: [0xffffffff, 0x87654321, 0xffffffff], expectedOutput: '0x87654321'},
      {input: [0xffffffff, 0xffffffff, 0x00000000], expectedOutput: '0xffffffff'},
      {input: [0xffffffff, 0xffffffff, 0x2648ace0], expectedOutput: '0xffffffff'},
      {input: [0xffffffff, 0xffffffff, 0xffffffff], expectedOutput: '0xffffffff'},
      {input: [0x7369c667, 0xec4aff51, 0xabbacd29], expectedOutput: '0xe8dacf49'},
      {input: [0x46e3fbf2, 0xf854c27c, 0x8de7e81b], expectedOutput: '0xc944c279'},
      {input: [0x632e5a76, 0x9ac99f33, 0xb70d3266], expectedOutput: '0x96093a32'},
      {input: [0x5aa35831, 0x17055d25, 0xd45ee958], expectedOutput: '0x965df969'},
      {input: [0xc6cdb2ab, 0x1154b49b, 0x4174820e], expectedOutput: '0x0174b08f'},
      {input: [0x87dc3d21, 0xa13ee970, 0x67fce141], expectedOutput: '0xe13ce960'},
      {input: [0x977e013e, 0x966bdcea, 0x2a5c388f], expectedOutput: '0xbe6a38ab'},
      {input: [0xfb3bb0ec, 0x543caf32, 0x5cdb18ec], expectedOutput: '0x54f8a820'},
      {input: [0x43fe1a02, 0x3aaafafb, 0xe6d129fb], expectedOutput: '0xa6ab3bfb'},
      {input: [0x947c3c05, 0x61bed875, 0xbb5cf989], expectedOutput: '0x2b3cd98d'},
      {input: [0x950f99a8, 0xb3f1ebb1, 0x00f7ef05], expectedOutput: '0x91f1efa5'},
      {input: [0xe53aa1e9, 0xd0cb0bca, 0xbd644748], expectedOutput: '0xd84e47c8'},
      {input: [0xa81e231f, 0xc5647b1c, 0xc55a7314], expectedOutput: '0xc544731c'},
      {input: [0x63794b5e, 0x2464703b, 0xdc099e11], expectedOutput: '0xbc60d41b'},
      {input: [0xf2acd4aa, 0x3baf101b, 0x50e3cd33], expectedOutput: '0x32ef191b'},
      {input: [0x5c154748, 0x19226fbb, 0xf57d9bba], expectedOutput: '0xb968dfba'},
      {input: [0x1c1ae10b, 0x29f8237f, 0x131ba4f8], expectedOutput: '0x0b1925fb'},
      {input: [0xe84ecab5, 0xe0383298, 0x343d4d79], expectedOutput: '0xf43907d8'},
      {input: [0x774e5fbc, 0x056ccbfa, 0x2b2186ac], expectedOutput: '0x0d6dcbb8'},
      {input: [0xa2551aaa, 0x73b570be, 0xd35c043b], expectedOutput: '0x731d14bb'},
      {input: [0xafb39436, 0x9ee4f0e2, 0x4915324f], expectedOutput: '0xcea4b26b'},
      {input: [0xa94e82fd, 0xb2d47008, 0x4854298a], expectedOutput: '0xe054290a'},
      {input: [0xd5bc0a9a, 0x44a8180e, 0x8ef35bac], expectedOutput: '0x4eeb592e'},
      {input: [0x9b2dd74c, 0x06e54209, 0xcdaf33c4], expectedOutput: '0x46a76288'},
      {input: [0x2d7f84a3, 0x4776d4ad, 0xec1c32de], expectedOutput: '0xc576b6fd'},
      {input: [0xf630c44a, 0x6c852320, 0x0407b2fb], expectedOutput: '0x640732b1'},
      {input: [0xb90becf4, 0xc386ba20, 0xecf1053e], expectedOutput: '0xc5f2a92a'},
      {input: [0xb73367d9, 0xe3a35099, 0x34d9d314], expectedOutput: '0xa3ebd09d'},
      {input: [0xf2a05ef7, 0x05f6a810, 0xb4be0194], expectedOutput: '0x04be0910'},
      {input: [0xfa7844bc, 0x23e66949, 0x69da1ad0], expectedOutput: '0x23e25a48'},
      {input: [0x7e4c7e6a, 0x48b32551, 0x943a5384], expectedOutput: '0xc83225c4'},
      {input: [0x909931fb, 0xee445732, 0xe5e9bc9b], expectedOutput: '0xe5609d32'},
      {input: [0xf508cf25, 0x535ee2e9, 0xb2d2aa60], expectedOutput: '0x53dae261'},
      {input: [0x54fa85d0, 0xd4e835d8, 0x98648266], expectedOutput: '0xdcec07f6'},
      {input: [0x7587a8d9, 0x8a5a7065, 0x2980623f], expectedOutput: '0x08026267'},
      {input: [0xa57cde44, 0x59574e89, 0xacad51d3], expectedOutput: '0x09d54f93'},
      {input: [0xec809586, 0xf185e417, 0xf1660c8c], expectedOutput: '0xf1e68c0e'},
      {input: [0xbb7cc07c, 0x66e4fc22, 0x630b61da], expectedOutput: '0x6267e1a2'},
      {input: [0x83bc62af, 0x3a2f69b4, 0x1627afff], expectedOutput: '0x162fedf4'},
      {input: [0x1f07ac93, 0x34116db8, 0x4fef8d2d], expectedOutput: '0x54e92dbc'},
      {input: [0x63b6d489, 0xe4c7c135, 0xd8678324], expectedOutput: '0xf8c7c325'},
      {input: [0xec1296ed, 0xd8023945, 0x9df80ae5], expectedOutput: '0xd9ea1845'},
      {input: [0xa5d10977, 0x1ff4c196, 0xca82aa95], expectedOutput: '0x4fd2a396'},
      {input: [0x90ae496c, 0xba6816cd, 0xf2a67aac], expectedOutput: '0xf22832cc'},
      {input: [0x99caa8b4, 0x2a37c2b2, 0x61cf08cb], expectedOutput: '0x680780fb'},
      {input: [0x5e80c3c9, 0xda28036e, 0x196ad74c], expectedOutput: '0x5b6a174c'},
      {input: [0x99d3d2ed, 0x008b794c, 0xd49a5622], expectedOutput: '0x448b544e'},
      {input: [0xe4fed118, 0xa345cdd9, 0xff01c691], expectedOutput: '0xbb45c799'},
      {input: [0x15d92ac9, 0xee2f4301, 0x61870215], expectedOutput: '0x640f0215'},
      {input: [0x9e62137c, 0x8172fc69, 0xa66571cd], expectedOutput: '0xa06770e9'},
      {input: [0xcf49ab3e, 0x3ace4b71, 0x764fa775], expectedOutput: '0x3a4e0f71'},
      {input: [0xff647eea, 0xfd61eb81, 0x679bc3fe], expectedOutput: '0xfdfbeb94'},
      {input: [0x8ce90dbf, 0xbd324e7e, 0x6a8c7cf9], expectedOutput: '0xee247c7e'},
      {input: [0x3ca45bc7, 0xedb2f402, 0xf3ec1672], expectedOutput: '0xefe85432'},
      {input: [0x00f04d01, 0xcf678b10, 0x175b5099], expectedOutput: '0x176b1998'},
      {input: [0x98d48e9f, 0xd103610a, 0xbe0da7bc], expectedOutput: '0xb609212a'},
      {input: [0x0eabbf9b, 0xd60198d5, 0xf6d6f2e5], expectedOutput: '0xf655d8f5'},
      {input: [0x16c53e7d, 0x2d2e218e, 0xb9c602af], expectedOutput: '0xad06208e'},
      {input: [0x1f8ac963, 0x0cde9770, 0x2b1a8956], expectedOutput: '0x2c9a8174'},
      {input: [0x07011b21, 0x8bfdd80d, 0xa4a1c216], expectedOutput: '0xa3a1d817'},
      {input: [0x92d2cfe3, 0x354b98d2, 0xd155d561], expectedOutput: '0x514798c2'},
      {input: [0xc2dd336c, 0xdeedf7bc, 0x20e5ef13], expectedOutput: '0xe2edff3f'},
      {input: [0xddabe2c7, 0x88814da4, 0xee1a531c], expectedOutput: '0xaa91519c'},
      {input: [0x4c2466eb, 0xa81e793b, 0x686afbac], expectedOutput: '0x284ef92f'},
      {input: [0x064658f3, 0x0e262b47, 0xb2ebd20d], expectedOutput: '0xb6af8a4f'},
      {input: [0x3b3a6c1f, 0xab2a54c0, 0xf6f84eba], expectedOutput: '0xefea46a0'},
      {input: [0x739e16c7, 0x04db0811, 0xa70a2260], expectedOutput: '0x849a2021'},
      {input: [0x5bb5314d, 0x220da003, 0xcd5d470d], expectedOutput: '0x864d6601'},
      {input: [0x5678879b, 0x9c4c70d5, 0x980fea86], expectedOutput: '0x9c4f6895'},
      {input: [0x539cebf2, 0x5afaa70d, 0xdbb5b0d8], expectedOutput: '0xdab9b308'},
      {input: [0x5dfdc250, 0xa52a5a09, 0xb7fba3e2], expectedOutput: '0xa72a63a2'},
      {input: [0x9a544713, 0x23326331, 0x5b76ce4e], expectedOutput: '0x4332cb5d'},
      {input: [0x4db67175, 0x71286b21, 0x37cf252e], expectedOutput: '0x7369652b'},
      {input: [0x62dcf980, 0xb019d79c, 0x4f4a6d1e], expectedOutput: '0x2d1ad59e'},
      {input: [0x1f737cd1, 0xc07be94a, 0x7b0d315a], expectedOutput: '0x607f694a'},
      {input: [0xcaed369c, 0xdb02bc5b, 0x523ddeb5], expectedOutput: '0xda10fc39'},
      {input: [0xd40257b6, 0x95244cc4, 0x12b597c8], expectedOutput: '0x96b5c4cc'},
      {input: [0xdbd23080, 0xfd56e061, 0x71c84316], expectedOutput: '0xf95a6316'},
      {input: [0xb54dcaff, 0x5e078aa8, 0xa63309e1], expectedOutput: '0x16378ba8'},
      {input: [0x1d3b5755, 0x6e2ff0ee, 0x81490220], expectedOutput: '0x8c6b5064'},
      {input: [0xf87fa0e2, 0xe36947e3, 0xb998b611], expectedOutput: '0xe1e916f3'},
      {input: [0x22189f41, 0xfdc84ba8, 0x901a04a2], expectedOutput: '0xb00a0ba2'},
      {input: [0x15fe49f4, 0x2d96484b, 0xcb2515e8], expectedOutput: '0xcf975c48'},
      {input: [0x6dae8f5c, 0x86274645, 0x8da93fe5], expectedOutput: '0x842736e5'},
      {input: [0x2c8a718a, 0x6abca475, 0x397fbaee], expectedOutput: '0x39fdaa64'},
      {input: [0xea671502, 0x87b68c2b, 0x61f5641b], expectedOutput: '0x83b6641b'},
      {input: [0x90e71cab, 0xe51e905b, 0x7711a802], expectedOutput: '0xe716b00b'},
      {input: [0x3be1cd4d, 0x8a746087, 0xa174db76], expectedOutput: '0x8a745237'},
      {input: [0x83282a68, 0x3ae41d8f, 0x94cacc39], expectedOutput: '0x16e2cc19'},
      {input: [0x5e79e85c, 0xded68a91, 0xdf19b757], expectedOutput: '0xdf509f13'},
      {input: [0x8e698d18, 0xd12fdd69, 0x97545708], expectedOutput: '0x913ddf08'},
      {input: [0xaed13975, 0x61439b05, 0x15c0bc84], expectedOutput: '0x31419d85'},
      {input: [0x9ef39647, 0x657d0c4d, 0x02f3e699], expectedOutput: '0x047164dd'},
      {input: [0xccd322c4, 0xef63287a, 0x669d3461], expectedOutput: '0xee4f3461'},
      {input: [0x53c7e0cf, 0xe468879d, 0x6b825b1d], expectedOutput: '0x68409b9d'},
      {input: [0x01d00067, 0xaa03c4e6, 0x6076d7e6], expectedOutput: '0x6026d7e6'},
      {input: [0x604fd9ff, 0xddc6ed0d, 0x6a308dcd], expectedOutput: '0x4a76cd0d'},
      {input: [0x324e9915, 0x5c9dd1f4, 0xb75d6ed1], expectedOutput: '0x951df7d4'},
      {input: [0x18626032, 0x3679d837, 0xbf96c8b2], expectedOutput: '0xb7f4c8b2'},
      {input: [0x839c5cb5, 0xffedcdea, 0x5a313c66], expectedOutput: '0xdbad6ce2'},
    ],
    testFunction: function(input) {
      return MD5.prototype.dwordToHex(MD5.prototype.f1(input[0], input[1], input[2]));
    }
  },

  {
    desc: 'All sample F2 inputs produce the expected output.',
    dataProvider: [
      {input: [0x00000000, 0x00000000, 0x00000000], expectedOutput: '0x00000000'},
      {input: [0x00000000, 0x00000000, 0x2648ace0], expectedOutput: '0x00000000'},
      {input: [0x00000000, 0x00000000, 0xffffffff], expectedOutput: '0x00000000'},
      {input: [0x00000000, 0x87654321, 0x00000000], expectedOutput: '0x87654321'},
      {input: [0x00000000, 0x87654321, 0x2648ace0], expectedOutput: '0x81254301'},
      {input: [0x00000000, 0x87654321, 0xffffffff], expectedOutput: '0x00000000'},
      {input: [0x00000000, 0xffffffff, 0x00000000], expectedOutput: '0xffffffff'},
      {input: [0x00000000, 0xffffffff, 0x2648ace0], expectedOutput: '0xd9b7531f'},
      {input: [0x00000000, 0xffffffff, 0xffffffff], expectedOutput: '0x00000000'},
      {input: [0x12345678, 0x00000000, 0x00000000], expectedOutput: '0x00000000'},
      {input: [0x12345678, 0x00000000, 0x2648ace0], expectedOutput: '0x02000460'},
      {input: [0x12345678, 0x00000000, 0xffffffff], expectedOutput: '0x12345678'},
      {input: [0x12345678, 0x87654321, 0x00000000], expectedOutput: '0x87654321'},
      {input: [0x12345678, 0x87654321, 0x2648ace0], expectedOutput: '0x83254761'},
      {input: [0x12345678, 0x87654321, 0xffffffff], expectedOutput: '0x12345678'},
      {input: [0x12345678, 0xffffffff, 0x00000000], expectedOutput: '0xffffffff'},
      {input: [0x12345678, 0xffffffff, 0x2648ace0], expectedOutput: '0xdbb7577f'},
      {input: [0x12345678, 0xffffffff, 0xffffffff], expectedOutput: '0x12345678'},
      {input: [0xffffffff, 0x00000000, 0x00000000], expectedOutput: '0x00000000'},
      {input: [0xffffffff, 0x00000000, 0x2648ace0], expectedOutput: '0x2648ace0'},
      {input: [0xffffffff, 0x00000000, 0xffffffff], expectedOutput: '0xffffffff'},
      {input: [0xffffffff, 0x87654321, 0x00000000], expectedOutput: '0x87654321'},
      {input: [0xffffffff, 0x87654321, 0x2648ace0], expectedOutput: '0xa76defe1'},
      {input: [0xffffffff, 0x87654321, 0xffffffff], expectedOutput: '0xffffffff'},
      {input: [0xffffffff, 0xffffffff, 0x00000000], expectedOutput: '0xffffffff'},
      {input: [0xffffffff, 0xffffffff, 0x2648ace0], expectedOutput: '0xffffffff'},
      {input: [0xffffffff, 0xffffffff, 0xffffffff], expectedOutput: '0xffffffff'},
      {input: [0xdeb6cf0d, 0x6f95133d, 0xab87f774], expectedOutput: '0xce96c70d'},
      {input: [0x82e200d0, 0x7e4178c9, 0xbf01ded5], expectedOutput: '0xc24020d8'},
      {input: [0x11beefab, 0x386bef2b, 0xfb1622be], expectedOutput: '0x117fefab'},
      {input: [0xa96aab35, 0x7355f2a3, 0xbbf537f2], expectedOutput: '0xe960e331'},
      {input: [0x843a36af, 0xbf433b14, 0x55d0012a], expectedOutput: '0xae133a3e'},
      {input: [0xaf8d3cf1, 0x93aba35e, 0xf23d154f], expectedOutput: '0xa38fb651'},
      {input: [0xfa659207, 0x78b55ac9, 0xa5fdef90], expectedOutput: '0xf8659249'},
      {input: [0x5564402b, 0x33ab3542, 0xcfe23871], expectedOutput: '0x75690523'},
      {input: [0x2b628ddc, 0xaa1d9fa3, 0xfaa48231], expectedOutput: '0x2a399d92'},
      {input: [0x6c735adc, 0x74117049, 0xf2ca76b0], expectedOutput: '0x645352d9'},
      {input: [0x1c2575ab, 0x89eb08ad, 0x38b44d95], expectedOutput: '0x996f45a9'},
      {input: [0x1ee3d1ed, 0x2f198753, 0x2b9c8ce1], expectedOutput: '0x0e8183f3'},
      {input: [0xac9fadfc, 0xce9f6923, 0x8ceac4de], expectedOutput: '0xce9fadfd'},
      {input: [0x6215d5cc, 0x109aca23, 0xef2e7d9b], expectedOutput: '0x7294d7a8'},
      {input: [0xe61e4705, 0xcf11bad3, 0x8b7cb168], expectedOutput: '0xc61d0b93'},
      {input: [0xf95a1b1a, 0xac8544df, 0x3d0e9a1a], expectedOutput: '0xb98b5edf'},
      {input: [0x004da864, 0x2bef7b26, 0x96110dc3], expectedOutput: '0x29ef7a64'},
      {input: [0x306623c8, 0xeebbe2d4, 0xdce715fd], expectedOutput: '0x327ee3c8'},
      {input: [0x74886c5a, 0x6bb19607, 0x656bfe3f], expectedOutput: '0x6e986c1a'},
      {input: [0x3c905a79, 0x30d3a168, 0x986039c4], expectedOutput: '0x38939868'},
      {input: [0x18871b1b, 0x8bf46e31, 0xe2ff7ddb], expectedOutput: '0x09871b3b'},
      {input: [0x524db013, 0x27b7b9ae, 0x7b644713], expectedOutput: '0x56d7b8bf'},
      {input: [0xadab37e9, 0x8b460b70, 0x58a3cd27], expectedOutput: '0x8be70771'},
      {input: [0x16e3973b, 0x28f8e214, 0x407a4692], expectedOutput: '0x28e2a616'},
      {input: [0x126732ff, 0x628ecb79, 0x72103902], expectedOutput: '0x128ef27b'},
      {input: [0x6cfd5645, 0x5ec4a023, 0x4c75a738], expectedOutput: '0x5ef50603'},
      {input: [0x1b746d89, 0xb25befb3, 0x9ac5c221], expectedOutput: '0x3a5e6d93'},
      {input: [0x90fd538e, 0xd1030d8c, 0x863d0063], expectedOutput: '0xd13f0d8e'},
      {input: [0xd9e401a1, 0x312559a8, 0x7a4c9ac7], expectedOutput: '0x596541a9'},
      {input: [0xaa2da789, 0xf844f26a, 0xd1884145], expectedOutput: '0xa84cb32b'},
      {input: [0xb1a38b4e, 0x2d37e08c, 0x8a061ce2], expectedOutput: '0xa533e84e'},
      {input: [0x3cbc2b75, 0x4eb708c5, 0x1af8e4b0], expectedOutput: '0x5cbf2875'},
      {input: [0x1b123dd6, 0xcdec9a7e, 0xb27e8f26], expectedOutput: '0x5f921d5e'},
      {input: [0x52dfb670, 0x47dce5d2, 0xd6849810], expectedOutput: '0x53dcf5d2'},
      {input: [0x51243ba1, 0xf56b1d1f, 0xd8107d5a], expectedOutput: '0x756b3905'},
      {input: [0x3da5fc17, 0xfcef248c, 0xac4eceda], expectedOutput: '0x7ca5ec16'},
      {input: [0xc4f32ab3, 0x649a77c3, 0xd1b5beb2], expectedOutput: '0xe4bb6bf3'},
      {input: [0x35c620db, 0xb40ed69d, 0x5ff2b3d3], expectedOutput: '0xb5ce64df'},
      {input: [0xb15be1d7, 0x635da9b0, 0x962751d3], expectedOutput: '0xf15be9f3'},
      {input: [0x7bfac1c8, 0x5b4caf80, 0x6c9113cf], expectedOutput: '0x7bdcadc8'},
      {input: [0xbc219fe9, 0x2a1b1352, 0xa4db76f4], expectedOutput: '0xae0117e2'},
      {input: [0xf308391f, 0x52892f8a, 0x71cd84f1], expectedOutput: '0x73082b1b'},
      {input: [0x03cc1a33, 0x166f5d2d, 0x4fd390fc], expectedOutput: '0x13ec5d31'},
      {input: [0x9879eea3, 0x843c5465, 0x1777448d], expectedOutput: '0x907954e1'},
      {input: [0x656a0174, 0xb8d63785, 0x7ebba251], expectedOutput: '0xe46e15d4'},
      {input: [0xfc952b00, 0x5f4b68bb, 0xbbf7c456], expectedOutput: '0xfc9d28a9'},
      {input: [0xa6403319, 0xecbeb778, 0x3d5128b8], expectedOutput: '0xe4eeb758'},
      {input: [0xb1f6275f, 0xc92fb1c9, 0x98c6c4dc], expectedOutput: '0xd1ef355d'},
      {input: [0x83f7112c, 0xef3eeed6, 0x99957e21], expectedOutput: '0xe7bf90f6'},
      {input: [0xee855336, 0xdb2cd67b, 0xc78c22fd], expectedOutput: '0xdea4d636'},
      {input: [0xb090bbd3, 0xac485680, 0x3e2f3f68], expectedOutput: '0xb0407bc0'},
      {input: [0x4e2d6e2d, 0x22e8c2ec, 0x91116d16], expectedOutput: '0x22e9eeec'},
      {input: [0x416c3d44, 0x3208f85f, 0x34e299b4], expectedOutput: '0x0268794f'},
      {input: [0x57e02aef, 0x96951069, 0x6ae5c27e], expectedOutput: '0xd6f0126f'},
      {input: [0x9b8dcd85, 0x7e2c9e3a, 0x3ac099db], expectedOutput: '0x5eac8fa1'},
      {input: [0x456cc891, 0x51794f61, 0xe3a85a79], expectedOutput: '0x51794d11'},
      {input: [0xe8793e6a, 0x85525e00, 0x6620df2b], expectedOutput: '0xe1721e2a'},
      {input: [0x58e44d7d, 0x7792a4e6, 0xcebdff6d], expectedOutput: '0x79a64def'},
      {input: [0xc71f364e, 0xfaaac890, 0x06e22406], expectedOutput: '0xfe0aec96'},
      {input: [0xae8c3582, 0x9214ac14, 0xdfeaf8f9], expectedOutput: '0x8e9c3484'},
      {input: [0x0a577d9d, 0xcad8147c, 0xdb91f84a], expectedOutput: '0x0a597c3c'},
      {input: [0xc6d53cc0, 0xe2ccb860, 0x019058ed], expectedOutput: '0xe2dcb8c0'},
      {input: [0xfe93a405, 0x3ade7e9d, 0x774435fb], expectedOutput: '0x7e9a6e05'},
      {input: [0x93411c49, 0xd46ed214, 0x6e9a440e], expectedOutput: '0x92649618'},
      {input: [0xe95167fc, 0xc4eae1bf, 0x23c37e86], expectedOutput: '0xe569e7bd'},
      {input: [0xf75da1fc, 0x1f6ea1d6, 0xd2b2afbd], expectedOutput: '0xdf5ca1fe'},
      {input: [0x90a62181, 0x61fe4165, 0x674a4fa8], expectedOutput: '0x00b601c5'},
      {input: [0xb72c3431, 0xaedaefb2, 0x66a53790], expectedOutput: '0xae7efc32'},
      {input: [0x958513d8, 0x446737c2, 0xbdd40e58], expectedOutput: '0xd5a733da'},
      {input: [0xf71ed24f, 0x535e6822, 0x4f0a8a9d], expectedOutput: '0x575ee22f'},
      {input: [0x09fee479, 0xf36fa31b, 0x7988f4b7], expectedOutput: '0x8befe739'},
      {input: [0x84bdf02c, 0x4d4291fe, 0x86446064], expectedOutput: '0xcd06f1be'},
      {input: [0x66d9a2c9, 0xa6b5e32d, 0xe2b0b3c7], expectedOutput: '0x6695e2e9'},
      {input: [0x0ed51f57, 0x40875d14, 0x4bc4454d], expectedOutput: '0x0ac71d55'},
      {input: [0x3a9806d6, 0x30c0dc67, 0xac96997f], expectedOutput: '0x38d04456'},
      {input: [0x43524b7c, 0x562502ff, 0x3664fa22], expectedOutput: '0x42414afd'},
      {input: [0xa576eb58, 0x07f13a30, 0xa8418941], expectedOutput: '0xa7f0bb70'},
      {input: [0xe5d80266, 0x18916e9b, 0xb85be3b9], expectedOutput: '0xa0d80e22'},
      {input: [0x080e81e6, 0xd33e727b, 0x8e79b45e], expectedOutput: '0x590ec267'},
      {input: [0x2f956aee, 0x59d7d7f3, 0x743eafd9], expectedOutput: '0x2dd57aea'},
      {input: [0xd78ccf1d, 0x998fe8b3, 0xe4a19e69], expectedOutput: '0xdd8eee9b'},
      {input: [0x6eb8df10, 0x81fd3193, 0x8eb1929b], expectedOutput: '0x0ffcb310'},
      {input: [0x42e88869, 0x55b72638, 0xa92c43f6], expectedOutput: '0x54bb2468'},
      {input: [0x9442bc2b, 0x6a79e35a, 0x55d931c2], expectedOutput: '0x3e60f21a'},
      {input: [0xfdd6d662, 0xd28b8768, 0x48147310], expectedOutput: '0xda9fd668'},
      {input: [0x909dcb9a, 0x3a39ca0f, 0xe0cf7b86], expectedOutput: '0x9abdcb8b'},
      {input: [0x204a485e, 0xdb752379, 0x62d84bf9], expectedOutput: '0xb96d6858'},
      {input: [0xe33463d3, 0x712b48d7, 0x2301c814], expectedOutput: '0x732a40d3'},
      {input: [0x185d3a92, 0x13f82cb5, 0xed334374], expectedOutput: '0x1ad92e91'},
      {input: [0x60c8a866, 0xc6c2a0f3, 0xdba9f604], expectedOutput: '0x44caa0f7'},
      {input: [0x524cd43e, 0x2f754d9d, 0x3c48d387], expectedOutput: '0x137ddc1e'},
      {input: [0x744f40ff, 0xea618283, 0x1d4a2a2a], expectedOutput: '0xf66b80ab'},
      {input: [0xcee40cca, 0x40a98d02, 0xff93f562], expectedOutput: '0xcea80c42'},
      {input: [0xc92e0842, 0xdb0576db, 0x3a4f54b7], expectedOutput: '0xc90e224a'},
      {input: [0x0024b0d6, 0xa51e6eda, 0x7c73027a], expectedOutput: '0x812c6cd2'},
      {input: [0xf1bd1d8f, 0x55f05012, 0x341e1f58], expectedOutput: '0x71fc5d0a'},
      {input: [0x4c0f2495, 0x4f875e78, 0xe94fab0e], expectedOutput: '0x4e8f7474'},
      {input: [0x948e6d1a, 0xff11016f, 0x31f0ce1e], expectedOutput: '0xde814d7b'},
      {input: [0x7686e11e, 0x95aaa400, 0x41e2b9c8], expectedOutput: '0xd48aa508'},
      {input: [0x26906917, 0x2e0fdf14, 0xbcc39d4d], expectedOutput: '0x268c4b15'},
    ],
    testFunction: function(input) {
      return MD5.prototype.dwordToHex(MD5.prototype.f2(input[0], input[1], input[2]));
    }
  },

  {
    desc: 'All sample F3 inputs produce the expected output.',
    dataProvider: [
      {input: [0x00000000, 0x00000000, 0x00000000], expectedOutput: '0x00000000'},
      {input: [0x00000000, 0x00000000, 0x2648ace0], expectedOutput: '0x2648ace0'},
      {input: [0x00000000, 0x00000000, 0xffffffff], expectedOutput: '0xffffffff'},
      {input: [0x00000000, 0x87654321, 0x00000000], expectedOutput: '0x87654321'},
      {input: [0x00000000, 0x87654321, 0x2648ace0], expectedOutput: '0xa12defc1'},
      {input: [0x00000000, 0x87654321, 0xffffffff], expectedOutput: '0x789abcde'},
      {input: [0x00000000, 0xffffffff, 0x00000000], expectedOutput: '0xffffffff'},
      {input: [0x00000000, 0xffffffff, 0x2648ace0], expectedOutput: '0xd9b7531f'},
      {input: [0x00000000, 0xffffffff, 0xffffffff], expectedOutput: '0x00000000'},
      {input: [0x12345678, 0x00000000, 0x00000000], expectedOutput: '0x12345678'},
      {input: [0x12345678, 0x00000000, 0x2648ace0], expectedOutput: '0x347cfa98'},
      {input: [0x12345678, 0x00000000, 0xffffffff], expectedOutput: '0xedcba987'},
      {input: [0x12345678, 0x87654321, 0x00000000], expectedOutput: '0x95511559'},
      {input: [0x12345678, 0x87654321, 0x2648ace0], expectedOutput: '0xb319b9b9'},
      {input: [0x12345678, 0x87654321, 0xffffffff], expectedOutput: '0x6aaeeaa6'},
      {input: [0x12345678, 0xffffffff, 0x00000000], expectedOutput: '0xedcba987'},
      {input: [0x12345678, 0xffffffff, 0x2648ace0], expectedOutput: '0xcb830567'},
      {input: [0x12345678, 0xffffffff, 0xffffffff], expectedOutput: '0x12345678'},
      {input: [0xffffffff, 0x00000000, 0x00000000], expectedOutput: '0xffffffff'},
      {input: [0xffffffff, 0x00000000, 0x2648ace0], expectedOutput: '0xd9b7531f'},
      {input: [0xffffffff, 0x00000000, 0xffffffff], expectedOutput: '0x00000000'},
      {input: [0xffffffff, 0x87654321, 0x00000000], expectedOutput: '0x789abcde'},
      {input: [0xffffffff, 0x87654321, 0x2648ace0], expectedOutput: '0x5ed2103e'},
      {input: [0xffffffff, 0x87654321, 0xffffffff], expectedOutput: '0x87654321'},
      {input: [0xffffffff, 0xffffffff, 0x00000000], expectedOutput: '0x00000000'},
      {input: [0xffffffff, 0xffffffff, 0x2648ace0], expectedOutput: '0x2648ace0'},
      {input: [0xffffffff, 0xffffffff, 0xffffffff], expectedOutput: '0xffffffff'},
      {input: [0xbdbbd49e, 0xc0eeaca2, 0x8d36748d], expectedOutput: '0xf0630cb1'},
      {input: [0xe122e118, 0xb222049a, 0x82d8b26d], expectedOutput: '0xd1d857ef'},
      {input: [0xdeb0e791, 0x229b7384, 0xe9df5647], expectedOutput: '0x15f4c252'},
      {input: [0x8fa9cd02, 0x5a1ce041, 0x5b3b3fc1], expectedOutput: '0x8e8e1282'},
      {input: [0xb10d5d43, 0xa033e50f, 0x507fe3cc], expectedOutput: '0x41415b80'},
      {input: [0x9e731a57, 0x73885270, 0x61023120], expectedOutput: '0x8cf97907'},
      {input: [0xd2bb1f11, 0xa12ef65e, 0x62523b53], expectedOutput: '0x11c7d21c'},
      {input: [0xed038521, 0xc03e8269, 0x0c5eb19c], expectedOutput: '0x2163b6d4'},
      {input: [0x237fe603, 0x29858218, 0xfffc40a1], expectedOutput: '0xf50624ba'},
      {input: [0x8aa02a37, 0x86edf365, 0xe174f078], expectedOutput: '0xed39292a'},
      {input: [0x0ea1b272, 0x661a0063, 0xfe8a9ae6], expectedOutput: '0x963128f7'},
      {input: [0xbd280f1c, 0x86bc244f, 0xb3115c4e], expectedOutput: '0x8885771d'},
      {input: [0xc83afe4f, 0x60a9aeee, 0xc36e4b60], expectedOutput: '0x6bfd1bc1'},
      {input: [0x3129884b, 0x3e30b322, 0x12fb58c2], expectedOutput: '0x1de263ab'},
      {input: [0xca98b77c, 0x637da914, 0x952bb7a7], expectedOutput: '0x3ccea9cf'},
      {input: [0xc5f5d565, 0x6b886320, 0x0e9cb2ec], expectedOutput: '0xa0e104a9'},
      {input: [0x284dcc65, 0xa03a4824, 0x146ad200], expectedOutput: '0x9c1d5641'},
      {input: [0x2377e87c, 0x05b9a39f, 0x98caae78], expectedOutput: '0xbe04e59b'},
      {input: [0xfe035312, 0x6a0c9f05, 0x9092596c], expectedOutput: '0x049d957b'},
      {input: [0xa231cca2, 0x1bb69b9f, 0x233e2d83], expectedOutput: '0x9ab97abe'},
      {input: [0x4828f7d0, 0xb8e0f2a6, 0x4ab6e345], expectedOutput: '0xba7ee633'},
      {input: [0xefb5c283, 0xbe7f471c, 0xb360b014], expectedOutput: '0xe2aa358b'},
      {input: [0xcfce164c, 0x14f20c43, 0xaa5c1a04], expectedOutput: '0x7160000b'},
      {input: [0x52623d0d, 0xa39d1820, 0xf69252da], expectedOutput: '0x076d77f7'},
      {input: [0xadb41299, 0x0e6014c2, 0x6ede2e2a], expectedOutput: '0xcd0a2871'},
      {input: [0x3f82d03b, 0xf8e9deeb, 0x3c4a4b1b], expectedOutput: '0xfb2145cb'},
      {input: [0x3ddfe763, 0xd3347239, 0x4680e884], expectedOutput: '0xa86b7dde'},
      {input: [0x2755e1fd, 0x4a95330f, 0xee891703], expectedOutput: '0x8349c5f1'},
      {input: [0x11e672f6, 0x204d31bd, 0x525e2d18], expectedOutput: '0x63f56e53'},
      {input: [0x2325929f, 0x7769a57a, 0x969fbe86], expectedOutput: '0xc2d38963'},
      {input: [0xf5e034f1, 0x42e36a4c, 0x9a53cadc], expectedOutput: '0x2d509461'},
      {input: [0x13baa1fb, 0x6d6518ce, 0x25908aaa], expectedOutput: '0x5b4f339f'},
      {input: [0xb69cf930, 0xa94c3bb8, 0xbc9e2d70], expectedOutput: '0xa34eeff8'},
      {input: [0x73fe8297, 0x470d514c, 0xc05ac8f2], expectedOutput: '0xf4a91b29'},
      {input: [0x8b2dc0e0, 0x7ab0bd4a, 0x6f314cb7], expectedOutput: '0x9eac311d'},
      {input: [0xf8187d88, 0x41b4b7aa, 0x85b5b239], expectedOutput: '0x3c19781b'},
      {input: [0xf6ccc203, 0x6bb6268a, 0x31f6e4e6], expectedOutput: '0xac8c006f'},
      {input: [0x58aba6a1, 0x7ac7dcf2, 0x0472e05a], expectedOutput: '0x261e9a09'},
      {input: [0xd0462697, 0xdc55fbd8, 0x48d221bd], expectedOutput: '0x44c1fcf2'},
      {input: [0x2eb38847, 0x0e5fa96c, 0x41660a4f], expectedOutput: '0x618a2b64'},
      {input: [0x41bc2ee7, 0xa5452e0e, 0x2d758b55], expectedOutput: '0xc98c8bbc'},
      {input: [0x4409ca86, 0x328cdbeb, 0xd0603f64], expectedOutput: '0xa6e52e09'},
      {input: [0x37debfe8, 0xb17845ca, 0x81f23473], expectedOutput: '0x0754ce51'},
      {input: [0xb8263763, 0x49e59bc3, 0x508def65], expectedOutput: '0xa14e43c5'},
      {input: [0x2e8219ca, 0x40ffe358, 0x6c77dda2], expectedOutput: '0x020a2730'},
      {input: [0x951df022, 0x87160f24, 0x0a3f3c47], expectedOutput: '0x1834c341'},
      {input: [0x3c5325d7, 0xde8ce114, 0x530d0ffa], expectedOutput: '0xb1d2cb39'},
      {input: [0x94930cf2, 0x0c010be9, 0x1fa11efb], expectedOutput: '0x873319e0'},
      {input: [0x75a7b82e, 0xcc7fe6f4, 0x1f08d20b], expectedOutput: '0xa6d08cd1'},
      {input: [0xaefe95b3, 0x96010ba4, 0x002a9417], expectedOutput: '0x38d50a00'},
      {input: [0x9a0c2b9f, 0x78baae4a, 0x5aed6166], expectedOutput: '0xb85be4b3'},
      {input: [0x53266c47, 0xf2722f3e, 0x68a070c4], expectedOutput: '0xc9f433bd'},
      {input: [0x92fea17b, 0xd5932835, 0x9e6f9f54], expectedOutput: '0xd902161a'},
      {input: [0xb316294d, 0xd20e038a, 0xad25346f], expectedOutput: '0xcc3d1ea8'},
      {input: [0x279f9763, 0x838f3f08, 0x16168de0], expectedOutput: '0xb206258b'},
      {input: [0x0aeba9b6, 0x96a85a48, 0x0e49be84], expectedOutput: '0x920a4d7a'},
      {input: [0x30e057c1, 0xefdd058c, 0xa5177d9d], expectedOutput: '0x7a2a2fd0'},
      {input: [0x9d28a6bc, 0xeab33e34, 0x30f49ee7], expectedOutput: '0x476f066f'},
      {input: [0x7cc69cf8, 0x1b8b0f5a, 0xf34b6b67], expectedOutput: '0x9406f8c5'},
      {input: [0x0ee22871, 0x62b3f9a5, 0xd4ffdba0], expectedOutput: '0xb8ae0a74'},
      {input: [0x01beb21a, 0x4831b250, 0xa8c5f74e], expectedOutput: '0xe14af704'},
      {input: [0x6ec35007, 0x2c610ebb, 0xdc3a4336], expectedOutput: '0x9e981d8a'},
      {input: [0xdd3eed3d, 0xe3b13dc9, 0x3fe46fef], expectedOutput: '0x016bbf1b'},
      {input: [0x6f871621, 0x14174c0d, 0x5882da9c], expectedOutput: '0x231280b0'},
      {input: [0x1e84e3e8, 0x64fabf27, 0x754138ac], expectedOutput: '0x0f3f6463'},
      {input: [0x6458f275, 0x82a33d61, 0x60f12b53], expectedOutput: '0x860ae447'},
      {input: [0x14750877, 0xca6cf7e2, 0x02e8f0db], expectedOutput: '0xdcf10f4e'},
      {input: [0x5c66e3af, 0x91d1a71b, 0xfaf52a99], expectedOutput: '0x37426e2d'},
      {input: [0xba7c9967, 0x3b1a6dc4, 0x574f8f75], expectedOutput: '0xd6297bd6'},
      {input: [0x6221bb87, 0x5b6409ac, 0x08b7caec], expectedOutput: '0x31f278c7'},
      {input: [0x0a998971, 0x1a048eb3, 0xebd48027], expectedOutput: '0xfb4987e5'},
      {input: [0x6227eeed, 0x05b9767e, 0xde67da32], expectedOutput: '0xb9f942a1'},
      {input: [0xd039cbe3, 0x06d8f195, 0x2d10717a], expectedOutput: '0xfbf14b0c'},
      {input: [0x274714ff, 0x81121b94, 0x87e33909], expectedOutput: '0x21b63662'},
      {input: [0xe28c9cb0, 0x59c0f376, 0x5329f9be], expectedOutput: '0xe8659678'},
      {input: [0x645901ea, 0x72916972, 0x1199d87d], expectedOutput: '0x0751b0e5'},
      {input: [0xfd92abf3, 0x958475e5, 0x87771111], expectedOutput: '0xef61cf07'},
      {input: [0xc3e13704, 0x1b160a30, 0x7e7f700c], expectedOutput: '0xa6884d38'},
      {input: [0x57f011d9, 0xdd6889e9, 0x1adafb35], expectedOutput: '0x90426305'},
      {input: [0x82af5e70, 0x7409266f, 0x8d37ea5d], expectedOutput: '0x7b919242'},
      {input: [0x01a84df5, 0x977f28bd, 0x22ee7039], expectedOutput: '0xb4391571'},
      {input: [0x2eff56f9, 0xc248d951, 0xa744f738], expectedOutput: '0x4bf37890'},
      {input: [0x7a1b4d1d, 0x2d085238, 0x5d2eb0a0], expectedOutput: '0x0a3daf85'},
      {input: [0x11f4add8, 0x1734e21d, 0x8a453339], expectedOutput: '0x8c857cfc'},
      {input: [0x454c8e0d, 0xa3ec9085, 0x161d08de], expectedOutput: '0xf0bd1656'},
      {input: [0xfa43255a, 0xae5871d6, 0x3cc04c1e], expectedOutput: '0x68db1892'},
      {input: [0x6853f42f, 0x34f29827, 0xac793f26], expectedOutput: '0xf0d8532e'},
      {input: [0xad4f66cf, 0xc8c36c6e, 0x68c30692], expectedOutput: '0x0d4f0c33'},
      {input: [0x96161b77, 0x96d2d667, 0xf2fe25ca], expectedOutput: '0xf23ae8da'},
      {input: [0xe426f1bd, 0xff90a030, 0x74addf06], expectedOutput: '0x6f1b8e8b'},
      {input: [0xdd3c704b, 0xee45ff77, 0x82845c1a], expectedOutput: '0xb1fdd326'},
      {input: [0xfd185632, 0x39ef177b, 0x381d1508], expectedOutput: '0xfcea5441'},
      {input: [0xbb37adb5, 0xd72fe48c, 0xccb56c55], expectedOutput: '0xa0ad256c'},
      {input: [0x86bafa6b, 0x89083f56, 0x11862095], expectedOutput: '0x1e34e5a8'},
      {input: [0x3f4a7537, 0x4077678a, 0xa0fbaf14], expectedOutput: '0xdfc6bda9'},
      {input: [0xe8772b93, 0x02b42c97, 0x7d886f27], expectedOutput: '0x974b6823'},
      {input: [0x430690ae, 0xe8548cb1, 0x8c289e01], expectedOutput: '0x277a821e'},
      {input: [0x19cc9f05, 0xe2b9c74e, 0x89ca31f2], expectedOutput: '0x72bf69b9'},
      {input: [0x848c7f5d, 0x9c0214ee, 0x56df08a5], expectedOutput: '0x4e516316'},
      {input: [0x963e3495, 0xd82266d2, 0x54f1ee06], expectedOutput: '0x1aedbc41'},
    ],
    testFunction: function(input) {
      return MD5.prototype.dwordToHex(MD5.prototype.f3(input[0], input[1], input[2]));
    }
  },

  {
    desc: 'All sample F4 inputs produce the expected output.',
    dataProvider: [
      {input: [0x00000000, 0x00000000, 0x00000000], expectedOutput: '0xffffffff'},
      {input: [0x00000000, 0x00000000, 0x2648ace0], expectedOutput: '0xd9b7531f'},
      {input: [0x00000000, 0x00000000, 0xffffffff], expectedOutput: '0x00000000'},
      {input: [0x00000000, 0x87654321, 0x00000000], expectedOutput: '0x789abcde'},
      {input: [0x00000000, 0x87654321, 0x2648ace0], expectedOutput: '0x5ed2103e'},
      {input: [0x00000000, 0x87654321, 0xffffffff], expectedOutput: '0x87654321'},
      {input: [0x00000000, 0xffffffff, 0x00000000], expectedOutput: '0x00000000'},
      {input: [0x00000000, 0xffffffff, 0x2648ace0], expectedOutput: '0x2648ace0'},
      {input: [0x00000000, 0xffffffff, 0xffffffff], expectedOutput: '0xffffffff'},
      {input: [0x12345678, 0x00000000, 0x00000000], expectedOutput: '0xffffffff'},
      {input: [0x12345678, 0x00000000, 0x2648ace0], expectedOutput: '0xdbb7577f'},
      {input: [0x12345678, 0x00000000, 0xffffffff], expectedOutput: '0x12345678'},
      {input: [0x12345678, 0x87654321, 0x00000000], expectedOutput: '0x789abcde'},
      {input: [0x12345678, 0x87654321, 0x2648ace0], expectedOutput: '0x5cd2145e'},
      {input: [0x12345678, 0x87654321, 0xffffffff], expectedOutput: '0x95511559'},
      {input: [0x12345678, 0xffffffff, 0x00000000], expectedOutput: '0x00000000'},
      {input: [0x12345678, 0xffffffff, 0x2648ace0], expectedOutput: '0x2448a880'},
      {input: [0x12345678, 0xffffffff, 0xffffffff], expectedOutput: '0xedcba987'},
      {input: [0xffffffff, 0x00000000, 0x00000000], expectedOutput: '0xffffffff'},
      {input: [0xffffffff, 0x00000000, 0x2648ace0], expectedOutput: '0xffffffff'},
      {input: [0xffffffff, 0x00000000, 0xffffffff], expectedOutput: '0xffffffff'},
      {input: [0xffffffff, 0x87654321, 0x00000000], expectedOutput: '0x789abcde'},
      {input: [0xffffffff, 0x87654321, 0x2648ace0], expectedOutput: '0x789abcde'},
      {input: [0xffffffff, 0x87654321, 0xffffffff], expectedOutput: '0x789abcde'},
      {input: [0xffffffff, 0xffffffff, 0x00000000], expectedOutput: '0x00000000'},
      {input: [0xffffffff, 0xffffffff, 0x2648ace0], expectedOutput: '0x00000000'},
      {input: [0xffffffff, 0xffffffff, 0xffffffff], expectedOutput: '0x00000000'},
      {input: [0xa836abb6, 0x393201dc, 0x6ebebe80], expectedOutput: '0x8045ea23'},
      {input: [0x770ac0d2, 0x5dcde9c8, 0xf0f40c1d], expectedOutput: '0x22c61a3a'},
      {input: [0x78c81672, 0xbbcdb905, 0x40630364], expectedOutput: '0x441147fe'},
      {input: [0x847a9504, 0x26f23853, 0xc09dfcf8], expectedOutput: '0x9988af54'},
      {input: [0x031e6be6, 0xe9f31277, 0x2d62bb28], expectedOutput: '0x3a6c7d80'},
      {input: [0xd9e82f75, 0x371a4c32, 0x35bb94e1], expectedOutput: '0xecf6234d'},
      {input: [0xc45baecc, 0x9084f8aa, 0xda94a263], expectedOutput: '0x75ff0776'},
      {input: [0xddc487b4, 0xb80a2643, 0x8791f355], expectedOutput: '0x45e4a9fd'},
      {input: [0x20beab3f, 0x0b557a3f, 0xd2cfb028], expectedOutput: '0x26eb95c0'},
      {input: [0x0c6354a9, 0xabe7f7f6, 0xc188ab7e], expectedOutput: '0x9590a35f'},
      {input: [0x267992d1, 0xc4ad0b85, 0xf6e56cb6], expectedOutput: '0xebd6985c'},
      {input: [0x0e013ae6, 0x94e0d1eb, 0x1ba04325], expectedOutput: '0x7abf6f15'},
      {input: [0xb9c6873a, 0x037a4e32, 0x6629f4e1], expectedOutput: '0xbaacc10c'},
      {input: [0xb52bd7ff, 0x29ab1043, 0x3537ad4a], expectedOutput: '0xd640c7bc'},
      {input: [0xa3c9177e, 0x95be6a5b, 0x244e85f1], expectedOutput: '0x6e471525'},
      {input: [0xb427c9d3, 0xbc1b51bd, 0x6b714628], expectedOutput: '0x08b4a86a'},
      {input: [0xa0941d56, 0x48d6cbca, 0x3deb9fe2], expectedOutput: '0xaa42b695'},
      {input: [0xfbd3a909, 0x021f212e, 0xa7b646ea], expectedOutput: '0xf9c49833'},
      {input: [0xbf63d197, 0x6d2ad517, 0xbc0ebef2], expectedOutput: '0x92d90488'},
      {input: [0x6c04e489, 0x8da9ef83, 0xc7887c98], expectedOutput: '0xf1de086c'},
      {input: [0x88c9a79e, 0x85307fed, 0x68449351], expectedOutput: '0x1acb9053'},
      {input: [0x5ad66f68, 0xb716e42d, 0x4b231ac8], expectedOutput: '0x49c80b52'},
      {input: [0xa2d8cc09, 0xe7696049, 0xf56f3207], expectedOutput: '0x4db1adb0'},
      {input: [0x027a9fb1, 0x9b6bbe33, 0x5bf6412d], expectedOutput: '0x3d1001c0'},
      {input: [0xed120c25, 0x30383527, 0x4ad21101], expectedOutput: '0xcd07dbd8'},
      {input: [0x79313b71, 0x1f6ea16d, 0x7321e840], expectedOutput: '0xe2919e92'},
      {input: [0xd40f8ca6, 0xf22f05cd, 0x38df4111], expectedOutput: '0x2500bb23'},
      {input: [0x77691876, 0x9ac23b29, 0xe413f377], expectedOutput: '0xe52f27d7'},
      {input: [0xd5038194, 0x10482569, 0x7fe457b1], expectedOutput: '0xc5538cb7'},
      {input: [0x6e71135c, 0xcaa65154, 0x92410f69], expectedOutput: '0xa559a28a'},
      {input: [0xc22c034b, 0x8ba640f7, 0x2b60aac1], expectedOutput: '0x5d191788'},
      {input: [0x803ba9cf, 0x5dff1f00, 0x86cb7132], expectedOutput: '0xa4c0b0cf'},
      {input: [0x2b5071c2, 0xccbd9181, 0x8c8ee995], expectedOutput: '0xb7cce66b'},
      {input: [0xeb173429, 0xad1678de, 0x212e5121], expectedOutput: '0x52c1c621'},
      {input: [0xa27e2d70, 0x6028499e, 0x3c8b78bb], expectedOutput: '0x8356e6ea'},
      {input: [0x9e084809, 0x5b2a9632, 0xa94642ca], expectedOutput: '0x85936b0f'},
      {input: [0xdb565cba, 0x1dfc84ad, 0x50bf7bb2], expectedOutput: '0xe2aa5852'},
      {input: [0x7fb1e7c4, 0x69bb3c5f, 0xb707c385], expectedOutput: '0x1642c3a1'},
      {input: [0x24123259, 0x2ecd5974, 0x630923b5], expectedOutput: '0x923ba72f'},
      {input: [0x5a8005a8, 0x45aa4080, 0x87c45b27], expectedOutput: '0x3f11e578'},
      {input: [0x1df08098, 0x9dd4f743, 0x9dc1e629], expectedOutput: '0xe22a6e9d'},
      {input: [0xf5cb8e3f, 0x5958d4b1, 0x5ab3d8da], expectedOutput: '0xac977b8e'},
      {input: [0x409f5e18, 0x51c764b9, 0x276eb7e4], expectedOutput: '0x89583aa2'},
      {input: [0xd8c442ae, 0x68758529, 0xc55d4113], expectedOutput: '0x92937bc7'},
      {input: [0xef1eb515, 0xa64ad28e, 0xe9e6e930], expectedOutput: '0x59556551'},
      {input: [0x313bad4d, 0x1359a964, 0x15eb1dec], expectedOutput: '0xe866463b'},
      {input: [0xb67d60a3, 0xb77bdba1, 0x1ea69a90], expectedOutput: '0x4006be4e'},
      {input: [0x9cc5f06c, 0x2785abda, 0xbd59c059], expectedOutput: '0xf9625434'},
      {input: [0x56d0b26a, 0x726bbbcf, 0xbd29e81c], expectedOutput: '0x24bd0c24'},
      {input: [0x5474a4c3, 0xaa721b3e, 0xe546370b], expectedOutput: '0xf48ff7c9'},
      {input: [0x3c0dcce3, 0xf6f9668c, 0xe74cca18], expectedOutput: '0xca469b6b'},
      {input: [0xa15ab785, 0x635f83a0, 0x66b7d327], expectedOutput: '0xda053c7d'},
      {input: [0xfa102aee, 0x44df5761, 0xaf80ec23], expectedOutput: '0xbea06c9f'},
      {input: [0x6aa67a52, 0xc952f244, 0x4a6bacaa], expectedOutput: '0x36e48913'},
      {input: [0x56adca2f, 0x8cbc659d, 0xf086cd8f], expectedOutput: '0xd3419fe2'},
      {input: [0x47356524, 0xa4f6b552, 0x730f9c2f], expectedOutput: '0x6b03d2a6'},
      {input: [0x393d618f, 0x3c83a80d, 0x0f923072], expectedOutput: '0xc5fe4782'},
      {input: [0x249b4f95, 0x4015211c, 0xd9874a87], expectedOutput: '0x66eedee1'},
      {input: [0x2f7d7dff, 0xa9a28c1a, 0xfae2dfed], expectedOutput: '0x86dff1e5'},
      {input: [0xf9366587, 0x2b09c995, 0x344fa418], expectedOutput: '0xd0bfb672'},
      {input: [0x4d7464c6, 0xae26fbae, 0x92dda378], expectedOutput: '0xc3508769'},
      {input: [0x1d3b7f30, 0xe6181d5f, 0x18e04e82], expectedOutput: '0x1927e222'},
      {input: [0x2f43e917, 0x5363928d, 0xa5a0d7f7], expectedOutput: '0x2c3c7b92'},
      {input: [0x4b53c6d2, 0x9add306a, 0x0fb719b0], expectedOutput: '0x6186d6b5'},
      {input: [0xb9f5cf36, 0x35d1d51e, 0x4c6514be], expectedOutput: '0x8e2e3a69'},
      {input: [0x9d9fc8a6, 0x724340a0, 0x70bd9606], expectedOutput: '0xed9ca95f'},
      {input: [0x770a9bc7, 0xea86c2b4, 0xafa37b91], expectedOutput: '0x9dd85d5b'},
      {input: [0x0fe57451, 0x2f5b4a88, 0xb2ccfb12], expectedOutput: '0x60ac3e75'},
      {input: [0x41250f3b, 0x6db2e2a6, 0x31e4bc7d], expectedOutput: '0xa28dad1d'},
      {input: [0x101c6a7e, 0x36bfbfe5, 0xbc46a434], expectedOutput: '0x6502c41a'},
      {input: [0x01eba1ee, 0xd7b3b89c, 0x6d19d8c7], expectedOutput: '0x445c1f62'},
      {input: [0x38dacbbb, 0x066abe87, 0x0e168628], expectedOutput: '0xff914578'},
      {input: [0x7944d545, 0x68368a7a, 0xc869212c], expectedOutput: '0x17e055ad'},
      {input: [0xa1a01dd9, 0xb00eb9f5, 0x0be9e984], expectedOutput: '0x45b8a60e'},
      {input: [0xd01153a7, 0x1ede27d9, 0x779822fd], expectedOutput: '0xc6a9f87e'},
      {input: [0xd9dfcead, 0xc9a149ef, 0x5b6a4166], expectedOutput: '0x347eb752'},
      {input: [0x7e0c78fa, 0x098af561, 0x21d99b48], expectedOutput: '0xf7a4899e'},
      {input: [0xc03fb7c3, 0x8637d7d9, 0x955f16a5], expectedOutput: '0x6c882802'},
      {input: [0xc55e015f, 0x3d21c842, 0xa2bb2d40], expectedOutput: '0xe07f1bbd'},
      {input: [0x6aab4522, 0xa48b84e1, 0x1464ca3b], expectedOutput: '0x4f30f107'},
      {input: [0x479b9ba2, 0x11dcfab1, 0x3ed63afb], expectedOutput: '0xd6672517'},
      {input: [0x437bf702, 0x46e53624, 0x5db0907c], expectedOutput: '0xa59ac9a7'},
      {input: [0x4f013b14, 0xa8636506, 0xb1effe00], expectedOutput: '0xe7725ef9'},
      {input: [0xf4c2ccf9, 0x09329906, 0xb54cad90], expectedOutput: '0xf7c147f9'},
      {input: [0x60fb31e4, 0xd5bdacc1, 0xed24bee7], expectedOutput: '0xa746dd3d'},
      {input: [0x23958723, 0x7fd48586, 0x57739751], expectedOutput: '0xd4496a29'},
      {input: [0xc060a630, 0x3775ac53, 0x9e9771dd], expectedOutput: '0xd61d0261'},
      {input: [0x0473541d, 0x35f29712, 0xa558871f], expectedOutput: '0x6b05ebef'},
      {input: [0x5d242d0c, 0xf4b597c4, 0x91b4153d], expectedOutput: '0x8bda780a'},
      {input: [0x9fc82ac2, 0xb83e609b, 0xc7bcb1b4], expectedOutput: '0x07f50e50'},
      {input: [0x68fcae49, 0x420d5536, 0x46a03182], expectedOutput: '0xbbf2bb4b'},
      {input: [0x063a55c8, 0x2c97ee6a, 0xb3cc5f18], expectedOutput: '0x62ac1b85'},
      {input: [0x746b0abf, 0x043b28bb, 0x0c6c37d6], expectedOutput: '0xf3c0e204'},
      {input: [0x0e4f798c, 0x7354efaa, 0xae798e44], expectedOutput: '0x2c9b9615'},
      {input: [0x95db107d, 0x2f49a76f, 0x6ca3b4b1], expectedOutput: '0xb896fc10'},
      {input: [0xb371dedc, 0xa2bfdd15, 0x01b00e57], expectedOutput: '0x5dc022e9'},
      {input: [0x417405fd, 0x10f0ed93, 0x6da6cbfd], expectedOutput: '0xc38dd86c'},
      {input: [0x239cef72, 0x808f3fa3, 0x3233001d], expectedOutput: '0x6f53c051'},
      {input: [0x35d4f2de, 0xfe368501, 0x1d40ab8a], expectedOutput: '0x09c973fe'},
      {input: [0x962e3098, 0x6d03d4fb, 0x66909fc3], expectedOutput: '0xf26ca447'},
    ],
    testFunction: function(input) {
      return MD5.prototype.dwordToHex(MD5.prototype.f4(input[0], input[1], input[2]));
    }
  },

  {
    desc: 'All sample MD5STEP inputs produce the expected output.',
    dataProvider: [
      {
        input: [MD5.prototype.f1, 0x8da93fe5, 0x2c8a718a, 0x6abca475, 0x397fbaee,
                0xea671502, 0x11], expectedOutput: '0x2b21d5a5'
      },
      {
        input: [MD5.prototype.f1, 0xfbe61fde, 0xfe2d1920, 0x0d33020c, 0x110b6987,
                0xad2e4b14, 0x1b], expectedOutput: '0xcbded77b'
      },
      {
        input: [MD5.prototype.f2, 0xfbe61fde, 0xfe2d1920, 0x0d33020c, 0x110b6987,
                0xad2e4b14, 0x1b], expectedOutput: '0xd45784cf'
      },
      {
        input: [MD5.prototype.f3, 0xfbe61fde, 0xfe2d1920, 0x0d33020c, 0x110b6987,
                0xad2e4b14, 0x1b], expectedOutput: '0xea86680c'
      },
      {
        input: [MD5.prototype.f4, 0xfbe61fde, 0xfe2d1920, 0x0d33020c, 0x110b6987,
                0xad2e4b14, 0x1b], expectedOutput: '0x33143163'
      },
      {
        input: [MD5.prototype.f1, 0x46307643, 0x73e5f3e3, 0x4093c35a, 0xeb5ab3be,
                0xe4ed66b1, 0x13], expectedOutput: '0x767d91b0'
      },
      {
        input: [MD5.prototype.f2, 0x46307643, 0x73e5f3e3, 0x4093c35a, 0xeb5ab3be,
                0xe4ed66b1, 0x13], expectedOutput: '0xfa9a6ae1'
      },
      {
        input: [MD5.prototype.f3, 0x46307643, 0x73e5f3e3, 0x4093c35a, 0xeb5ab3be,
                0xe4ed66b1, 0x13], expectedOutput: '0x73be0e35'
      },
      {
        input: [MD5.prototype.f4, 0x46307643, 0x73e5f3e3, 0x4093c35a, 0xeb5ab3be,
                0xe4ed66b1, 0x13], expectedOutput: '0x41510883'
      },
      {
        input: [MD5.prototype.f1, 0x62857e4d, 0x450fb4ca, 0x41bc5210, 0x7d349f98,
                0xa6408e13, 0x0f], expectedOutput: '0x58c7f5cb'
      },
      {
        input: [MD5.prototype.f2, 0x62857e4d, 0x450fb4ca, 0x41bc5210, 0x7d349f98,
                0xa6408e13, 0x0f], expectedOutput: '0xb583dbf3'
      },
      {
        input: [MD5.prototype.f3, 0x62857e4d, 0x450fb4ca, 0x41bc5210, 0x7d349f98,
                0xa6408e13, 0x0f], expectedOutput: '0x07e0f5f0'
      },
      {
        input: [MD5.prototype.f4, 0x62857e4d, 0x450fb4ca, 0x41bc5210, 0x7d349f98,
                0xa6408e13, 0x0f], expectedOutput: '0x1ebf7c66'
      },
      {
        input: [MD5.prototype.f1, 0x0ae92959, 0x02eed78f, 0xd1803b4b, 0xac854a9d,
                0x4cfe9590, 0x16], expectedOutput: '0x83eff1c5'
      },
      {
        input: [MD5.prototype.f2, 0x0ae92959, 0x02eed78f, 0xd1803b4b, 0xac854a9d,
                0x4cfe9590, 0x16], expectedOutput: '0xb119329b'
      },
      {
        input: [MD5.prototype.f3, 0x0ae92959, 0x02eed78f, 0xd1803b4b, 0xac854a9d,
                0x4cfe9590, 0x16], expectedOutput: '0x53a4cc68'
      },
      {
        input: [MD5.prototype.f4, 0x0ae92959, 0x02eed78f, 0xd1803b4b, 0xac854a9d,
                0x4cfe9590, 0x16], expectedOutput: '0xe6657131'
      },
      {
        input: [MD5.prototype.f1, 0xfe130beb, 0x68a45399, 0x3b91fd51, 0xf5122007,
                0xa3315d22, 0x0e], expectedOutput: '0x1f2d6b4e'
      },
      {
        input: [MD5.prototype.f2, 0xfe130beb, 0x68a45399, 0x3b91fd51, 0xf5122007,
                0xa3315d22, 0x0e], expectedOutput: '0xfa3bd68a'
      },
      {
        input: [MD5.prototype.f3, 0xfe130beb, 0x68a45399, 0x3b91fd51, 0xf5122007,
                0xa3315d22, 0x0e], expectedOutput: '0x669b6573'
      },
      {
        input: [MD5.prototype.f4, 0xfe130beb, 0x68a45399, 0x3b91fd51, 0xf5122007,
                0xa3315d22, 0x0e], expectedOutput: '0x8b91d049'
      },
      {
        input: [MD5.prototype.f1, 0x7d7bb3ed, 0x1fc97949, 0x232ab510, 0x5877c4b3,
                0xbe55c82c, 0x03], expectedOutput: '0x184b07a4'
      },
      {
        input: [MD5.prototype.f2, 0x7d7bb3ed, 0x1fc97949, 0x232ab510, 0x5877c4b3,
                0xbe55c82c, 0x03], expectedOutput: '0xd8a0e21c'
      },
      {
        input: [MD5.prototype.f3, 0x7d7bb3ed, 0x1fc97949, 0x232ab510, 0x5877c4b3,
                0xbe55c82c, 0x03], expectedOutput: '0x22f5a166'
      },
      {
        input: [MD5.prototype.f4, 0x7d7bb3ed, 0x1fc97949, 0x232ab510, 0x5877c4b3,
                0xbe55c82c, 0x03], expectedOutput: '0xe573ccff'
      },
      {
        input: [MD5.prototype.f1, 0x015215de, 0xa1a48373, 0xcd559152, 0xd8469e0f,
                0xe88d56bd, 0x1a], expectedOutput: '0x88b11b9a'
      },
      {
        input: [MD5.prototype.f2, 0x015215de, 0xa1a48373, 0xcd559152, 0xd8469e0f,
                0xe88d56bd, 0x1a], expectedOutput: '0x5b605732'
      },
      {
        input: [MD5.prototype.f3, 0x015215de, 0xa1a48373, 0xcd559152, 0xd8469e0f,
                0xe88d56bd, 0x1a], expectedOutput: '0xc81edf56'
      },
      {
        input: [MD5.prototype.f4, 0x015215de, 0xa1a48373, 0xcd559152, 0xd8469e0f,
                0xe88d56bd, 0x1a], expectedOutput: '0x92f7a2ef'
      },
      {
        input: [MD5.prototype.f1, 0xd899f1ac, 0xbd96eeb9, 0x9ed2754b, 0x1a214576,
                0x3cab73e7, 0x00], expectedOutput: '0x718fb99b'
      },
      {
        input: [MD5.prototype.f2, 0xd899f1ac, 0xbd96eeb9, 0x9ed2754b, 0x1a214576,
                0x3cab73e7, 0x00], expectedOutput: '0x6faec885'
      },
      {
        input: [MD5.prototype.f3, 0xd899f1ac, 0xbd96eeb9, 0x9ed2754b, 0x1a214576,
                0x3cab73e7, 0x00], expectedOutput: '0x0c4232d0'
      },
      {
        input: [MD5.prototype.f4, 0xd899f1ac, 0xbd96eeb9, 0x9ed2754b, 0x1a214576,
                0x3cab73e7, 0x00], expectedOutput: '0x35e8e03e'
      },
      {
        input: [MD5.prototype.f1, 0x979387da, 0x577f20dd, 0xfa482b61, 0x9ae90204,
                0x910f34bf, 0x12], expectedOutput: '0xd2e72e88'
      },
      {
        input: [MD5.prototype.f2, 0x979387da, 0x577f20dd, 0xfa482b61, 0x9ae90204,
                0x910f34bf, 0x12], expectedOutput: '0xef798d0c'
      },
      {
        input: [MD5.prototype.f3, 0x979387da, 0x577f20dd, 0xfa482b61, 0x9ae90204,
                0x910f34bf, 0x12], expectedOutput: '0x70c4a2e0'
      },
      {
        input: [MD5.prototype.f4, 0x979387da, 0x577f20dd, 0xfa482b61, 0x9ae90204,
                0x910f34bf, 0x12], expectedOutput: '0xa45df847'
      },
      {
        input: [MD5.prototype.f1, 0xbe9ff4d7, 0xa8fa4b67, 0x982fd405, 0xebb90c6b,
                0xac161a64, 0x15], expectedOutput: '0x12010791'
      },
      {
        input: [MD5.prototype.f2, 0xbe9ff4d7, 0xa8fa4b67, 0x982fd405, 0xebb90c6b,
                0xac161a64, 0x15], expectedOutput: '0x9d3eba03'
      },
      {
        input: [MD5.prototype.f3, 0xbe9ff4d7, 0xa8fa4b67, 0x982fd405, 0xebb90c6b,
                0xac161a64, 0x15], expectedOutput: '0xf1830fbb'
      },
      {
        input: [MD5.prototype.f4, 0xbe9ff4d7, 0xa8fa4b67, 0x982fd405, 0xebb90c6b,
                0xac161a64, 0x15], expectedOutput: '0x8eac3c4e'
      },
      {
        input: [MD5.prototype.f1, 0x6db5feae, 0x05ffc432, 0xe9f9d64a, 0x8e346094,
                0x37623a08, 0x12], expectedOutput: '0x7af0887a'
      },
      {
        input: [MD5.prototype.f2, 0x6db5feae, 0x05ffc432, 0xe9f9d64a, 0x8e346094,
                0x37623a08, 0x12], expectedOutput: '0x423ff08a'
      },
      {
        input: [MD5.prototype.f3, 0x6db5feae, 0x05ffc432, 0xe9f9d64a, 0x8e346094,
                0x37623a08, 0x12], expectedOutput: '0xb487e15c'
      },
      {
        input: [MD5.prototype.f4, 0x6db5feae, 0x05ffc432, 0xe9f9d64a, 0x8e346094,
                0x37623a08, 0x12], expectedOutput: '0x0d9cc8ab'
      },
      {
        input: [MD5.prototype.f1, 0xa8b88b44, 0xbb54cfa6, 0x9eb903e9, 0x6f63eb70,
                0xe945adf0, 0x16], expectedOutput: '0x0470dbfd'
      },
      {
        input: [MD5.prototype.f2, 0xa8b88b44, 0xbb54cfa6, 0x9eb903e9, 0x6f63eb70,
                0xe945adf0, 0x16], expectedOutput: '0xf2a84567'
      },
      {
        input: [MD5.prototype.f3, 0xa8b88b44, 0xbb54cfa6, 0x9eb903e9, 0x6f63eb70,
                0xe945adf0, 0x16], expectedOutput: '0xd84bf2be'
      },
      {
        input: [MD5.prototype.f4, 0xa8b88b44, 0xbb54cfa6, 0x9eb903e9, 0x6f63eb70,
                0xe945adf0, 0x16], expectedOutput: '0x1a02a8ab'
      },
      {
        input: [MD5.prototype.f1, 0x5267cb4a, 0xd78ac905, 0x4f63ce97, 0xca1e0976,
                0x7dcd08c4, 0x06], expectedOutput: '0xaa71ea4c'
      },
      {
        input: [MD5.prototype.f2, 0x5267cb4a, 0xd78ac905, 0x4f63ce97, 0xca1e0976,
                0x7dcd08c4, 0x06], expectedOutput: '0xbfb3adea'
      },
      {
        input: [MD5.prototype.f3, 0x5267cb4a, 0xd78ac905, 0x4f63ce97, 0xca1e0976,
                0x7dcd08c4, 0x06], expectedOutput: '0xa283858d'
      },
      {
        input: [MD5.prototype.f4, 0x5267cb4a, 0xd78ac905, 0x4f63ce97, 0xca1e0976,
                0x7dcd08c4, 0x06], expectedOutput: '0x06cc1327'
      },
      {
        input: [MD5.prototype.f1, 0x59ad0968, 0x4d42f3b6, 0x34188ccc, 0x69fd1ddf,
                0x573794f4, 0x04], expectedOutput: '0xa765a653'
      },
      {
        input: [MD5.prototype.f2, 0x59ad0968, 0x4d42f3b6, 0x34188ccc, 0x69fd1ddf,
                0x573794f4, 0x04], expectedOutput: '0x2f95f2d6'
      },
      {
        input: [MD5.prototype.f3, 0x59ad0968, 0x4d42f3b6, 0x34188ccc, 0x69fd1ddf,
                0x573794f4, 0x04], expectedOutput: '0x660303d2'
      },
      {
        input: [MD5.prototype.f4, 0x59ad0968, 0x4d42f3b6, 0x34188ccc, 0x69fd1ddf,
                0x573794f4, 0x04], expectedOutput: '0x1134d11f'
      },
      {
        input: [MD5.prototype.f1, 0x24770260, 0xb1a1450a, 0x30ba0a83, 0xa5237163,
                0xd632f0be, 0x04], expectedOutput: '0xa6637d1c'
      },
      {
        input: [MD5.prototype.f2, 0x24770260, 0xb1a1450a, 0x30ba0a83, 0xa5237163,
                0xd632f0be, 0x04], expectedOutput: '0x77d52f14'
      },
      {
        input: [MD5.prototype.f3, 0x24770260, 0xb1a1450a, 0x30ba0a83, 0xa5237163,
                0xd632f0be, 0x04], expectedOutput: '0x9fc4658b'
      },
      {
        input: [MD5.prototype.f4, 0x24770260, 0xb1a1450a, 0x30ba0a83, 0xa5237163,
                0xd632f0be, 0x04], expectedOutput: '0x10bcc8c6'
      },
      {
        input: [MD5.prototype.f1, 0xe77a21f3, 0x9a3fb1b6, 0xd59c9f5e, 0x651aa7c4,
                0x126f9d58, 0x0e], expectedOutput: '0x2fe82d77'
      },
      {
        input: [MD5.prototype.f2, 0xe77a21f3, 0x9a3fb1b6, 0xd59c9f5e, 0x651aa7c4,
                0x126f9d58, 0x0e], expectedOutput: '0xb87a1458'
      },
      {
        input: [MD5.prototype.f3, 0xe77a21f3, 0x9a3fb1b6, 0xd59c9f5e, 0x651aa7c4,
                0x126f9d58, 0x0e], expectedOutput: '0x6c5d7ade'
      },
      {
        input: [MD5.prototype.f4, 0xe77a21f3, 0x9a3fb1b6, 0xd59c9f5e, 0x651aa7c4,
                0x126f9d58, 0x0e], expectedOutput: '0xe3cac409'
      },
      {
        input: [MD5.prototype.f1, 0x4178f183, 0x0517aae1, 0x35270abb, 0x31e6ddf2,
                0x13d04477, 0x19], expectedOutput: '0x602e0c0c'
      },
      {
        input: [MD5.prototype.f2, 0x4178f183, 0x0517aae1, 0x35270abb, 0x31e6ddf2,
                0x13d04477, 0x19], expectedOutput: '0xcbcc4c62'
      },
      {
        input: [MD5.prototype.f3, 0x4178f183, 0x0517aae1, 0x35270abb, 0x31e6ddf2,
                0x13d04477, 0x19], expectedOutput: '0x49c5ea48'
      },
      {
        input: [MD5.prototype.f4, 0x4178f183, 0x0517aae1, 0x35270abb, 0x31e6ddf2,
                0x13d04477, 0x19], expectedOutput: '0xa5b6ae8d'
      },
      {
        input: [MD5.prototype.f1, 0x12fa34ba, 0x9f2569d1, 0xb491a83c, 0x015e72ea,
                0x9f0c1978, 0x0e], expectedOutput: '0x01407b69'
      },
      {
        input: [MD5.prototype.f2, 0x12fa34ba, 0x9f2569d1, 0xb491a83c, 0x015e72ea,
                0x9f0c1978, 0x0e], expectedOutput: '0xace703b4'
      },
      {
        input: [MD5.prototype.f3, 0x12fa34ba, 0x9f2569d1, 0xb491a83c, 0x015e72ea,
                0x9f0c1978, 0x0e], expectedOutput: '0xdf73e10d'
      },
      {
        input: [MD5.prototype.f4, 0x12fa34ba, 0x9f2569d1, 0xb491a83c, 0x015e72ea,
                0x9f0c1978, 0x0e], expectedOutput: '0x442c691f'
      },
      {
        input: [MD5.prototype.f1, 0xf32f347c, 0x9106ff78, 0x8ec5c194, 0xf8f797d3,
                0xc7a13336, 0x07], expectedOutput: '0x741ba249'
      },
      {
        input: [MD5.prototype.f2, 0xf32f347c, 0x9106ff78, 0x8ec5c194, 0xf8f797d3,
                0xc7a13336, 0x07], expectedOutput: '0xfca682a0'
      },
      {
        input: [MD5.prototype.f3, 0xf32f347c, 0x9106ff78, 0x8ec5c194, 0xf8f797d3,
                0xc7a13336, 0x07], expectedOutput: '0x938f7849'
      },
      {
        input: [MD5.prototype.f4, 0xf32f347c, 0x9106ff78, 0x8ec5c194, 0xf8f797d3,
                0xc7a13336, 0x07], expectedOutput: '0xdeda4ce2'
      },
      {
        input: [MD5.prototype.f1, 0xb28c453a, 0xac51985e, 0xc5e0cd96, 0xc6c558c0,
                0xaf8759ea, 0x07], expectedOutput: '0x18857572'
      },
      {
        input: [MD5.prototype.f2, 0xb28c453a, 0xac51985e, 0xc5e0cd96, 0xc6c558c0,
                0xaf8759ea, 0x07], expectedOutput: '0x66efd5d1'
      },
      {
        input: [MD5.prototype.f3, 0xb28c453a, 0xac51985e, 0xc5e0cd96, 0xc6c558c0,
                0xaf8759ea, 0x07], expectedOutput: '0x7027ae66'
      },
      {
        input: [MD5.prototype.f4, 0xb28c453a, 0xac51985e, 0xc5e0cd96, 0xc6c558c0,
                0xaf8759ea, 0x07], expectedOutput: '0x03da9f4b'
      },
      {
        input: [MD5.prototype.f1, 0x7d53de46, 0xf944f412, 0x0c3f7e7f, 0x81a49d30,
                0x2a4e3b4a, 0x00], expectedOutput: '0xa98b8ad4'
      },
      {
        input: [MD5.prototype.f2, 0x7d53de46, 0xf944f412, 0x0c3f7e7f, 0x81a49d30,
                0x2a4e3b4a, 0x00], expectedOutput: '0x2e070401'
      },
      {
        input: [MD5.prototype.f3, 0x7d53de46, 0xf944f412, 0x0c3f7e7f, 0x81a49d30,
                0x2a4e3b4a, 0x00], expectedOutput: '0x15c624ff'
      },
      {
        input: [MD5.prototype.f4, 0x7d53de46, 0xf944f412, 0x0c3f7e7f, 0x81a49d30,
                0x2a4e3b4a, 0x00], expectedOutput: '0x94479642'
      },
      {
        input: [MD5.prototype.f1, 0x6dd5c583, 0x051c5c1e, 0x0be463b7, 0x24fff6e0,
                0x2ea37fef, 0x0b], expectedOutput: '0x0e5fa211'
      },
      {
        input: [MD5.prototype.f2, 0x6dd5c583, 0x051c5c1e, 0x0be463b7, 0x24fff6e0,
                0x2ea37fef, 0x0b], expectedOutput: '0xb1f0a97a'
      },
      {
        input: [MD5.prototype.f3, 0x6dd5c583, 0x051c5c1e, 0x0be463b7, 0x24fff6e0,
                0x2ea37fef, 0x0b], expectedOutput: '0x0d923a52'
      },
      {
        input: [MD5.prototype.f4, 0x6dd5c583, 0x051c5c1e, 0x0be463b7, 0x24fff6e0,
                0x2ea37fef, 0x0b], expectedOutput: '0x913d2fa9'
      },
      {
        input: [MD5.prototype.f1, 0x16552fcc, 0x6b40a36a, 0x8730c3b2, 0x4de34f30,
                0x38b09b54, 0x06], expectedOutput: '0x15a737ff'
      },
      {
        input: [MD5.prototype.f2, 0x16552fcc, 0x6b40a36a, 0x8730c3b2, 0x4de34f30,
                0x38b09b54, 0x06], expectedOutput: '0x00d453f0'
      },
      {
        input: [MD5.prototype.f3, 0x16552fcc, 0x6b40a36a, 0x8730c3b2, 0x4de34f30,
                0x38b09b54, 0x06], expectedOutput: '0x917f65a6'
      },
      {
        input: [MD5.prototype.f4, 0x16552fcc, 0x6b40a36a, 0x8730c3b2, 0x4de34f30,
                0x38b09b54, 0x06], expectedOutput: '0x47cf82dc'
      },
      {
        input: [MD5.prototype.f1, 0x1eb4a52e, 0xaf4c5724, 0x80df182b, 0x6f23492e,
                0xe532d5b4, 0x1c], expectedOutput: '0x7b91c054'
      },
      {
        input: [MD5.prototype.f2, 0x1eb4a52e, 0xaf4c5724, 0x80df182b, 0x6f23492e,
                0xe532d5b4, 0x1c], expectedOutput: '0x2a8893e4'
      },
      {
        input: [MD5.prototype.f3, 0x1eb4a52e, 0xaf4c5724, 0x80df182b, 0x6f23492e,
                0xe532d5b4, 0x1c], expectedOutput: '0xe395cf34'
      },
      {
        input: [MD5.prototype.f4, 0x1eb4a52e, 0xaf4c5724, 0x80df182b, 0x6f23492e,
                0xe532d5b4, 0x1c], expectedOutput: '0xb37b0dd0'
      },
      {
        input: [MD5.prototype.f1, 0x88b04034, 0x81c160db, 0xa426eff0, 0x5afc4b0d,
                0xd97227fa, 0x07], expectedOutput: '0xb12b61f9'
      },
      {
        input: [MD5.prototype.f2, 0x88b04034, 0x81c160db, 0xa426eff0, 0x5afc4b0d,
                0xd97227fa, 0x07], expectedOutput: '0xf467f45e'
      },
      {
        input: [MD5.prototype.f3, 0x88b04034, 0x81c160db, 0xa426eff0, 0x5afc4b0d,
                0xd97227fa, 0x07], expectedOutput: '0x20d78b4b'
      },
      {
        input: [MD5.prototype.f4, 0x88b04034, 0x81c160db, 0xa426eff0, 0x5afc4b0d,
                0xd97227fa, 0x07], expectedOutput: '0x8582fd8d'
      },
      {
        input: [MD5.prototype.f1, 0xd710ca23, 0xfcbc42a0, 0x553cf0a5, 0x3ab51779,
                0xbf29a598, 0x0a], expectedOutput: '0xdbd31651'
      },
      {
        input: [MD5.prototype.f2, 0xd710ca23, 0xfcbc42a0, 0x553cf0a5, 0x3ab51779,
                0xbf29a598, 0x0a], expectedOutput: '0xda05beef'
      },
      {
        input: [MD5.prototype.f3, 0xd710ca23, 0xfcbc42a0, 0x553cf0a5, 0x3ab51779,
                0xbf29a598, 0x0a], expectedOutput: '0xbd111f45'
      },
      {
        input: [MD5.prototype.f4, 0xd710ca23, 0xfcbc42a0, 0x553cf0a5, 0x3ab51779,
                0xbf29a598, 0x0a], expectedOutput: '0xeee33b9b'
      },
      {
        input: [MD5.prototype.f1, 0x0491460a, 0x14de036d, 0xb4de01a4, 0x95f77ed8,
                0xb7859c7b, 0x12], expectedOutput: '0x95c34bc6'
      },
      {
        input: [MD5.prototype.f2, 0x0491460a, 0x14de036d, 0xb4de01a4, 0x95f77ed8,
                0xb7859c7b, 0x12], expectedOutput: '0xaca5c740'
      },
      {
        input: [MD5.prototype.f3, 0x0491460a, 0x14de036d, 0xb4de01a4, 0x95f77ed8,
                0xb7859c7b, 0x12], expectedOutput: '0x8f39cba6'
      },
      {
        input: [MD5.prototype.f4, 0x0491460a, 0x14de036d, 0xb4de01a4, 0x95f77ed8,
                0xb7859c7b, 0x12], expectedOutput: '0xaa201bca'
      },
      {
        input: [MD5.prototype.f1, 0x6738a7cf, 0x9726624d, 0x2add3099, 0x132d4a35,
                0x3c14d25e, 0x06], expectedOutput: '0xedcefbf6'
      },
      {
        input: [MD5.prototype.f2, 0x6738a7cf, 0x9726624d, 0x2add3099, 0x132d4a35,
                0x3c14d25e, 0x06], expectedOutput: '0x67a19104'
      },
      {
        input: [MD5.prototype.f3, 0x6738a7cf, 0x9726624d, 0x2add3099, 0x132d4a35,
                0x3c14d25e, 0x06], expectedOutput: '0x200b25e1'
      },
      {
        input: [MD5.prototype.f4, 0x6738a7cf, 0x9726624d, 0x2add3099, 0x132d4a35,
                0x3c14d25e, 0x06], expectedOutput: '0xb576c32b'
      },
      {
        input: [MD5.prototype.f1, 0x36817dbb, 0x0ced071a, 0x3eb3bc05, 0x4aa00024,
                0x747b3997, 0x03], expectedOutput: '0xd9dae2d1'
      },
      {
        input: [MD5.prototype.f2, 0x36817dbb, 0x0ced071a, 0x3eb3bc05, 0x4aa00024,
                0x747b3997, 0x03], expectedOutput: '0x4a70a1b9'
      },
      {
        input: [MD5.prototype.f3, 0x36817dbb, 0x0ced071a, 0x3eb3bc05, 0x4aa00024,
                0x747b3997, 0x03], expectedOutput: '0x2cc89b83'
      },
      {
        input: [MD5.prototype.f4, 0x36817dbb, 0x0ced071a, 0x3eb3bc05, 0x4aa00024,
                0x747b3997, 0x03], expectedOutput: '0x7f34e09b'
      },
      {
        input: [MD5.prototype.f1, 0x1cc390be, 0xe959d762, 0x456614c3, 0x374c804a,
                0x40f4518c, 0x0f], expectedOutput: '0xe4a431df'
      },
      {
        input: [MD5.prototype.f2, 0x1cc390be, 0xe959d762, 0x456614c3, 0x374c804a,
                0x40f4518c, 0x0f], expectedOutput: '0x24e0b6f3'
      },
      {
        input: [MD5.prototype.f3, 0x1cc390be, 0xe959d762, 0x456614c3, 0x374c804a,
                0x40f4518c, 0x0f], expectedOutput: '0x7c74d3f7'
      },
      {
        input: [MD5.prototype.f4, 0x1cc390be, 0xe959d762, 0x456614c3, 0x374c804a,
                0x40f4518c, 0x0f], expectedOutput: '0xd018dc8c'
      },
      {
        input: [MD5.prototype.f1, 0xd8622f40, 0xcb4cdd68, 0x505c0b8d, 0x8027be27,
                0x0e94eba7, 0x10], expectedOutput: '0x114304ce'
      },
      {
        input: [MD5.prototype.f2, 0xd8622f40, 0xcb4cdd68, 0x505c0b8d, 0x8027be27,
                0x0e94eba7, 0x10], expectedOutput: '0x83dc94bb'
      },
      {
        input: [MD5.prototype.f3, 0xd8622f40, 0xcb4cdd68, 0x505c0b8d, 0x8027be27,
                0x0e94eba7, 0x10], expectedOutput: '0x4ef5df96'
      },
      {
        input: [MD5.prototype.f4, 0xd8622f40, 0xcb4cdd68, 0x505c0b8d, 0x8027be27,
                0x0e94eba7, 0x10], expectedOutput: '0xbca973df'
      },
      {
        input: [MD5.prototype.f1, 0x1b167c8e, 0x5d5b0acd, 0x848c9b22, 0xc062f573,
                0x1ccbefc0, 0x00], expectedOutput: '0x1966764d'
      },
      {
        input: [MD5.prototype.f2, 0x1b167c8e, 0x5d5b0acd, 0x848c9b22, 0xc062f573,
                0x1ccbefc0, 0x00], expectedOutput: '0xda0b815c'
      },
      {
        input: [MD5.prototype.f3, 0x1b167c8e, 0x5d5b0acd, 0x848c9b22, 0xc062f573,
                0x1ccbefc0, 0x00], expectedOutput: '0xaef2dbb7'
      },
      {
        input: [MD5.prototype.f4, 0x1b167c8e, 0x5d5b0acd, 0x848c9b22, 0xc062f573,
                0x1ccbefc0, 0x00], expectedOutput: '0x9091090a'
      },
      {
        input: [MD5.prototype.f1, 0x827367db, 0x82900752, 0xfcfe1fe6, 0x9506cc3a,
                0xb5302829, 0x0c], expectedOutput: '0x2886f425'
      },
      {
        input: [MD5.prototype.f2, 0x827367db, 0x82900752, 0xfcfe1fe6, 0x9506cc3a,
                0xb5302829, 0x0c], expectedOutput: '0x3d0da95b'
      },
      {
        input: [MD5.prototype.f3, 0x827367db, 0x82900752, 0xfcfe1fe6, 0x9506cc3a,
                0xb5302829, 0x0c], expectedOutput: '0x48d92982'
      },
      {
        input: [MD5.prototype.f4, 0x827367db, 0x82900752, 0xfcfe1fe6, 0x9506cc3a,
                0xb5302829, 0x0c], expectedOutput: '0x2e135c2c'
      },
      {
        input: [MD5.prototype.f1, 0x6b640eaa, 0x3e872ffe, 0x94a56221, 0x759cf8e5,
                0x7994827a, 0x1e], expectedOutput: '0x8d2cd0cf'
      },
      {
        input: [MD5.prototype.f2, 0x6b640eaa, 0x3e872ffe, 0x94a56221, 0x759cf8e5,
                0x7994827a, 0x1e], expectedOutput: '0x64ee9f00'
      },
      {
        input: [MD5.prototype.f3, 0x6b640eaa, 0x3e872ffe, 0x94a56221, 0x759cf8e5,
                0x7994827a, 0x1e], expectedOutput: '0xefb50195'
      },
      {
        input: [MD5.prototype.f4, 0x6b640eaa, 0x3e872ffe, 0x94a56221, 0x759cf8e5,
                0x7994827a, 0x1e], expectedOutput: '0x0255e7be'
      },
      {
        input: [MD5.prototype.f1, 0x6e638445, 0x582394ac, 0x9c67ce38, 0xc0cb6539,
                0x4823eca3, 0x01], expectedOutput: '0xf70a40ee'
      },
      {
        input: [MD5.prototype.f2, 0x6e638445, 0x582394ac, 0x9c67ce38, 0xc0cb6539,
                0x4823eca3, 0x01], expectedOutput: '0x7d8192cc'
      },
      {
        input: [MD5.prototype.f3, 0x6e638445, 0x582394ac, 0x9c67ce38, 0xc0cb6539,
                0x4823eca3, 0x01], expectedOutput: '0xce50f5d7'
      },
      {
        input: [MD5.prototype.f4, 0x6e638445, 0x582394ac, 0x9c67ce38, 0xc0cb6539,
                0x4823eca3, 0x01], expectedOutput: '0x8bd31829'
      },
      {
        input: [MD5.prototype.f1, 0xbb7d1d40, 0x1d34129f, 0x44a179e0, 0x0ad84de7,
                0x0cd810a5, 0x0c], expectedOutput: '0xf5f06f92'
      },
      {
        input: [MD5.prototype.f2, 0xbb7d1d40, 0x1d34129f, 0x44a179e0, 0x0ad84de7,
                0x0cd810a5, 0x0c], expectedOutput: '0x831ad3e7'
      },
      {
        input: [MD5.prototype.f3, 0xbb7d1d40, 0x1d34129f, 0x44a179e0, 0x0ad84de7,
                0x0cd810a5, 0x0c], expectedOutput: '0x427be459'
      },
      {
        input: [MD5.prototype.f4, 0xbb7d1d40, 0x1d34129f, 0x44a179e0, 0x0ad84de7,
                0x0cd810a5, 0x0c], expectedOutput: '0xdcca5abd'
      },
      {
        input: [MD5.prototype.f1, 0x14d27771, 0xe45df563, 0x7a019dfd, 0x8c8ca058,
                0x5e056dbd, 0x11], expectedOutput: '0xd9adac15'
      },
      {
        input: [MD5.prototype.f2, 0x14d27771, 0xe45df563, 0x7a019dfd, 0x8c8ca058,
                0x5e056dbd, 0x11], expectedOutput: '0x2a84c72e'
      },
      {
        input: [MD5.prototype.f3, 0x14d27771, 0xe45df563, 0x7a019dfd, 0x8c8ca058,
                0x5e056dbd, 0x11], expectedOutput: '0x404700b4'
      },
      {
        input: [MD5.prototype.f4, 0x14d27771, 0xe45df563, 0x7a019dfd, 0x8c8ca058,
                0x5e056dbd, 0x11], expectedOutput: '0x72edf60f'
      },
      {
        input: [MD5.prototype.f1, 0x51f789ab, 0x455dcf99, 0xb3bccfe1, 0x40a81fe3,
                0x05dea504, 0x1f], expectedOutput: '0x722756e2'
      },
      {
        input: [MD5.prototype.f2, 0x51f789ab, 0x455dcf99, 0xb3bccfe1, 0x40a81fe3,
                0x05dea504, 0x1f], expectedOutput: '0x6ad74eb1'
      },
      {
        input: [MD5.prototype.f3, 0x51f789ab, 0x455dcf99, 0xb3bccfe1, 0x40a81fe3,
                0x05dea504, 0x1f], expectedOutput: '0x4c6d76be'
      },
      {
        input: [MD5.prototype.f4, 0x51f789ab, 0x455dcf99, 0xb3bccfe1, 0x40a81fe3,
                0x05dea504, 0x1f], expectedOutput: '0x17ba772e'
      },
      {
        input: [MD5.prototype.f1, 0x63c3aca6, 0xcac2c819, 0xac536db5, 0x1c7becbe,
                0xedeb5c31, 0x0f], expectedOutput: '0x058a3f2e'
      },
      {
        input: [MD5.prototype.f2, 0x63c3aca6, 0xcac2c819, 0xac536db5, 0x1c7becbe,
                0xedeb5c31, 0x0f], expectedOutput: '0xb3bb4511'
      },
      {
        input: [MD5.prototype.f3, 0x63c3aca6, 0xcac2c819, 0xac536db5, 0x1c7becbe,
                0xedeb5c31, 0x0f], expectedOutput: '0x73b7ae65'
      },
      {
        input: [MD5.prototype.f4, 0x63c3aca6, 0xcac2c819, 0xac536db5, 0x1c7becbe,
                0xedeb5c31, 0x0f], expectedOutput: '0x2aa494bb'
      },
      {
        input: [MD5.prototype.f1, 0x100fb70c, 0x7c16ed5c, 0xe628bc23, 0xe1af411f,
                0x5e4f640b, 0x10], expectedOutput: '0x43314164'
      },
      {
        input: [MD5.prototype.f2, 0x100fb70c, 0x7c16ed5c, 0xe628bc23, 0xe1af411f,
                0x5e4f640b, 0x10], expectedOutput: '0x946ac1c2'
      },
      {
        input: [MD5.prototype.f3, 0x100fb70c, 0x7c16ed5c, 0xe628bc23, 0xe1af411f,
                0x5e4f640b, 0x10], expectedOutput: '0xa78ed74c'
      },
      {
        input: [MD5.prototype.f4, 0x100fb70c, 0x7c16ed5c, 0xe628bc23, 0xe1af411f,
                0x5e4f640b, 0x10], expectedOutput: '0xdb0cf439'
      },
      {
        input: [MD5.prototype.f1, 0x7b298b4a, 0xf76814e8, 0xf2af74e3, 0x9bdf0b85,
                0xaf570287, 0x09], expectedOutput: '0x76c38132'
      },
      {
        input: [MD5.prototype.f2, 0x7b298b4a, 0xf76814e8, 0xf2af74e3, 0x9bdf0b85,
                0xaf570287, 0x09], expectedOutput: '0xc96d7b23'
      },
      {
        input: [MD5.prototype.f3, 0x7b298b4a, 0xf76814e8, 0xf2af74e3, 0x9bdf0b85,
                0xaf570287, 0x09], expectedOutput: '0x295ad479'
      },
      {
        input: [MD5.prototype.f4, 0x7b298b4a, 0xf76814e8, 0xf2af74e3, 0x9bdf0b85,
                0xaf570287, 0x09], expectedOutput: '0x8783e948'
      },
      {
        input: [MD5.prototype.f1, 0xfb5898f0, 0x0c59a7fc, 0xde97a3b4, 0x86f27f1e,
                0x26fbd577, 0x07], expectedOutput: '0x908eb6d4'
      },
      {
        input: [MD5.prototype.f2, 0xfb5898f0, 0x0c59a7fc, 0xde97a3b4, 0x86f27f1e,
                0x26fbd577, 0x07], expectedOutput: '0x6164b9bb'
      },
      {
        input: [MD5.prototype.f3, 0xfb5898f0, 0x0c59a7fc, 0xde97a3b4, 0x86f27f1e,
                0x26fbd577, 0x07], expectedOutput: '0x54ce86b7'
      },
      {
        input: [MD5.prototype.f4, 0xfb5898f0, 0x0c59a7fc, 0xde97a3b4, 0x86f27f1e,
                0x26fbd577, 0x07], expectedOutput: '0x1b93005f'
      },
      {
        input: [MD5.prototype.f1, 0xb91ba631, 0x926872a9, 0x402a59e8, 0xaee72654,
                0xc9519c32, 0x1a], expectedOutput: '0x1124e506'
      },
      {
        input: [MD5.prototype.f2, 0xb91ba631, 0x926872a9, 0x402a59e8, 0xaee72654,
                0xc9519c32, 0x1a], expectedOutput: '0xbf7bc9a1'
      },
      {
        input: [MD5.prototype.f3, 0xb91ba631, 0x926872a9, 0x402a59e8, 0xaee72654,
                0xc9519c32, 0x1a], expectedOutput: '0x7664bbe6'
      },
      {
        input: [MD5.prototype.f4, 0xb91ba631, 0x926872a9, 0x402a59e8, 0xaee72654,
                0xc9519c32, 0x1a], expectedOutput: '0x2abf723b'
      },
      {
        input: [MD5.prototype.f1, 0xc0f66c49, 0x09e6f142, 0x8cb01771, 0x39fe59d0,
                0x1592e7eb, 0x07], expectedOutput: '0xaa9df349'
      },
      {
        input: [MD5.prototype.f2, 0xc0f66c49, 0x09e6f142, 0x8cb01771, 0x39fe59d0,
                0x1592e7eb, 0x07], expectedOutput: '0x41bcbbf4'
      },
      {
        input: [MD5.prototype.f3, 0xc0f66c49, 0x09e6f142, 0x8cb01771, 0x39fe59d0,
                0x1592e7eb, 0x07], expectedOutput: '0xa2f0fd0b'
      },
      {
        input: [MD5.prototype.f4, 0xc0f66c49, 0x09e6f142, 0x8cb01771, 0x39fe59d0,
                0x1592e7eb, 0x07], expectedOutput: '0xfa811a4e'
      },
      {
        input: [MD5.prototype.f1, 0x6d940f3b, 0x2536e6ab, 0x4c917f56, 0x253ed33f,
                0x8d3dafdd, 0x1c], expectedOutput: '0x15258a0d'
      },
      {
        input: [MD5.prototype.f2, 0x6d940f3b, 0x2536e6ab, 0x4c917f56, 0x253ed33f,
                0x8d3dafdd, 0x1c], expectedOutput: '0x5bbf8183'
      },
      {
        input: [MD5.prototype.f3, 0x6d940f3b, 0x2536e6ab, 0x4c917f56, 0x253ed33f,
                0x8d3dafdd, 0x1c], expectedOutput: '0xc9ad9748'
      },
      {
        input: [MD5.prototype.f4, 0x6d940f3b, 0x2536e6ab, 0x4c917f56, 0x253ed33f,
                0x8d3dafdd, 0x1c], expectedOutput: '0x801a6bb8'
      },
      {
        input: [MD5.prototype.f1, 0xd1463ae6, 0x49e6d821, 0x535821bf, 0xc439038e,
                0xb9448f28, 0x1c], expectedOutput: '0x1ee514fc'
      },
      {
        input: [MD5.prototype.f2, 0xd1463ae6, 0x49e6d821, 0x535821bf, 0xc439038e,
                0xb9448f28, 0x1c], expectedOutput: '0x47c586c4'
      },
      {
        input: [MD5.prototype.f3, 0xd1463ae6, 0x49e6d821, 0x535821bf, 0xc439038e,
                0xb9448f28, 0x1c], expectedOutput: '0x30780462'
      },
      {
        input: [MD5.prototype.f4, 0xd1463ae6, 0x49e6d821, 0x535821bf, 0xc439038e,
                0xb9448f28, 0x1c], expectedOutput: '0x151b729e'
      },
      {
        input: [MD5.prototype.f1, 0x6aa91a8d, 0x05f7e6c9, 0x3a40ddf3, 0x941261ae,
                0x02b5d1aa, 0x05], expectedOutput: '0xb9ee2aa8'
      },
      {
        input: [MD5.prototype.f2, 0x6aa91a8d, 0x05f7e6c9, 0x3a40ddf3, 0x941261ae,
                0x02b5d1aa, 0x05], expectedOutput: '0x7c3508dc'
      },
      {
        input: [MD5.prototype.f3, 0x6aa91a8d, 0x05f7e6c9, 0x3a40ddf3, 0x941261ae,
                0x02b5d1aa, 0x05], expectedOutput: '0x2680c02c'
      },
      {
        input: [MD5.prototype.f4, 0x6aa91a8d, 0x05f7e6c9, 0x3a40ddf3, 0x941261ae,
                0x02b5d1aa, 0x05], expectedOutput: '0x69b9d301'
      },
      {
        input: [MD5.prototype.f1, 0x2d075e05, 0xcae74bee, 0x78e474cf, 0xd55eadde,
                0xf3b251b3, 0x0b], expectedOutput: '0x7f8bffe3'
      },
      {
        input: [MD5.prototype.f2, 0x2d075e05, 0xcae74bee, 0x78e474cf, 0xd55eadde,
                0xf3b251b3, 0x0b], expectedOutput: '0xcb33843b'
      },
      {
        input: [MD5.prototype.f3, 0x2d075e05, 0xcae74bee, 0x78e474cf, 0xd55eadde,
                0xf3b251b3, 0x0b], expectedOutput: '0x84fd082e'
      },
      {
        input: [MD5.prototype.f4, 0x2d075e05, 0xcae74bee, 0x78e474cf, 0xd55eadde,
                0xf3b251b3, 0x0b], expectedOutput: '0xb1de1183'
      },
      {
        input: [MD5.prototype.f1, 0xfff49e54, 0x9401a96f, 0xf3f307ec, 0x1b3fe134,
                0x8f8f0eab, 0x06], expectedOutput: '0x44bd4839'
      },
      {
        input: [MD5.prototype.f2, 0xfff49e54, 0x9401a96f, 0xf3f307ec, 0x1b3fe134,
                0x8f8f0eab, 0x06], expectedOutput: '0xa556e44f'
      },
      {
        input: [MD5.prototype.f3, 0xfff49e54, 0x9401a96f, 0xf3f307ec, 0x1b3fe134,
                0x8f8f0eab, 0x06], expectedOutput: '0xa840d6f2'
      },
      {
        input: [MD5.prototype.f4, 0xfff49e54, 0x9401a96f, 0xf3f307ec, 0x1b3fe134,
                0x8f8f0eab, 0x06], expectedOutput: '0x419aea14'
      },
      {
        input: [MD5.prototype.f1, 0xef42e43c, 0xc1e2f435, 0x485f3754, 0x37f1ce36,
                0x563edd63, 0x11], expectedOutput: '0xc14e6bde'
      },
      {
        input: [MD5.prototype.f2, 0xef42e43c, 0xc1e2f435, 0x485f3754, 0x37f1ce36,
                0x563edd63, 0x11], expectedOutput: '0x300a1316'
      },
      {
        input: [MD5.prototype.f3, 0xef42e43c, 0xc1e2f435, 0x485f3754, 0x37f1ce36,
                0x563edd63, 0x11], expectedOutput: '0x5fcefbd0'
      },
      {
        input: [MD5.prototype.f4, 0xef42e43c, 0xc1e2f435, 0x485f3754, 0x37f1ce36,
                0x563edd63, 0x11], expectedOutput: '0xca74829c'
      },
      {
        input: [MD5.prototype.f1, 0xe28e1037, 0xa4711e1e, 0xce88ad8b, 0x7fc2bd9d,
                0xddb6177e, 0x1f], expectedOutput: '0xf45488be'
      },
      {
        input: [MD5.prototype.f2, 0xe28e1037, 0xa4711e1e, 0xce88ad8b, 0x7fc2bd9d,
                0xddb6177e, 0x1f], expectedOutput: '0x56b74007'
      },
      {
        input: [MD5.prototype.f3, 0xe28e1037, 0xa4711e1e, 0xce88ad8b, 0x7fc2bd9d,
                0xddb6177e, 0x1f], expectedOutput: '0x8f30b8fc'
      },
      {
        input: [MD5.prototype.f4, 0xe28e1037, 0xa4711e1e, 0xce88ad8b, 0x7fc2bd9d,
                0xddb6177e, 0x1f], expectedOutput: '0xba0e2bf3'
      },
      {
        input: [MD5.prototype.f1, 0x0f2451ac, 0xff65622e, 0x640f9cd5, 0xef822d7e,
                0x599c0dd1, 0x1b], expectedOutput: '0x8dcf9d94'
      },
      {
        input: [MD5.prototype.f2, 0x0f2451ac, 0xff65622e, 0x640f9cd5, 0xef822d7e,
                0x599c0dd1, 0x1b], expectedOutput: '0x6223d2af'
      },
      {
        input: [MD5.prototype.f3, 0x0f2451ac, 0xff65622e, 0x640f9cd5, 0xef822d7e,
                0x599c0dd1, 0x1b], expectedOutput: '0x1652abc6'
      },
      {
        input: [MD5.prototype.f4, 0x0f2451ac, 0xff65622e, 0x640f9cd5, 0xef822d7e,
                0x599c0dd1, 0x1b], expectedOutput: '0xb786f89d'
      },
      {
        input: [MD5.prototype.f1, 0x95b99e17, 0x14736fb5, 0x80651f5c, 0x93e2942e,
                0xa32fb893, 0x1c], expectedOutput: '0xa0401f11'
      },
      {
        input: [MD5.prototype.f2, 0x95b99e17, 0x14736fb5, 0x80651f5c, 0x93e2942e,
                0xa32fb893, 0x1c], expectedOutput: '0xf9087616'
      },
      {
        input: [MD5.prototype.f3, 0x95b99e17, 0x14736fb5, 0x80651f5c, 0x93e2942e,
                0xa32fb893, 0x1c], expectedOutput: '0x2881536c'
      },
      {
        input: [MD5.prototype.f4, 0x95b99e17, 0x14736fb5, 0x80651f5c, 0x93e2942e,
                0xa32fb893, 0x1c], expectedOutput: '0x47c3ac2a'
      },
      {
        input: [MD5.prototype.f1, 0xa29c9ed0, 0x87fb38ab, 0x2b251272, 0x1b9adaa8,
                0x543af6ee, 0x16], expectedOutput: '0x7fffb704'
      },
      {
        input: [MD5.prototype.f2, 0xa29c9ed0, 0x87fb38ab, 0x2b251272, 0x1b9adaa8,
                0x543af6ee, 0x16], expectedOutput: '0x3601de56'
      },
      {
        input: [MD5.prototype.f3, 0xa29c9ed0, 0x87fb38ab, 0x2b251272, 0x1b9adaa8,
                0x543af6ee, 0x16], expectedOutput: '0x13e6bfcc'
      },
      {
        input: [MD5.prototype.f4, 0xa29c9ed0, 0x87fb38ab, 0x2b251272, 0x1b9adaa8,
                0x543af6ee, 0x16], expectedOutput: '0xdaec251c'
      },
      {
        input: [MD5.prototype.f1, 0x7bfb59e8, 0x2d1e2a11, 0x73cbefd7, 0x8cab7691,
                0x229f1dfd, 0x08], expectedOutput: '0x7314a051'
      },
      {
        input: [MD5.prototype.f2, 0x7bfb59e8, 0x2d1e2a11, 0x73cbefd7, 0x8cab7691,
                0x229f1dfd, 0x08], expectedOutput: '0x1241662e'
      },
      {
        input: [MD5.prototype.f3, 0x7bfb59e8, 0x2d1e2a11, 0x73cbefd7, 0x8cab7691,
                0x229f1dfd, 0x08], expectedOutput: '0x46496682'
      },
      {
        input: [MD5.prototype.f4, 0x7bfb59e8, 0x2d1e2a11, 0x73cbefd7, 0x8cab7691,
                0x229f1dfd, 0x08], expectedOutput: '0x5cdab7bc'
      },
      {
        input: [MD5.prototype.f1, 0xeb62e3fc, 0x503f9cd9, 0xffa92704, 0xc129baa2,
                0xb2b000e7, 0x13], expectedOutput: '0xa86b16b9'
      },
      {
        input: [MD5.prototype.f2, 0xeb62e3fc, 0x503f9cd9, 0xffa92704, 0xc129baa2,
                0xb2b000e7, 0x13], expectedOutput: '0x637882bd'
      },
      {
        input: [MD5.prototype.f3, 0xeb62e3fc, 0x503f9cd9, 0xffa92704, 0xc129baa2,
                0xb2b000e7, 0x13], expectedOutput: '0x83500368'
      },
      {
        input: [MD5.prototype.f4, 0xeb62e3fc, 0x503f9cd9, 0xffa92704, 0xc129baa2,
                0xb2b000e7, 0x13], expectedOutput: '0x4e209827'
      },
      {
        input: [MD5.prototype.f1, 0x26cd1e28, 0x84486c3c, 0x156745b3, 0x6fb14130,
                0x3a96b591, 0x14], expectedOutput: '0x12e5818d'
      },
      {
        input: [MD5.prototype.f2, 0x26cd1e28, 0x84486c3c, 0x156745b3, 0x6fb14130,
                0x3a96b591, 0x14], expectedOutput: '0x0b0fc6dd'
      },
      {
        input: [MD5.prototype.f3, 0x26cd1e28, 0x84486c3c, 0x156745b3, 0x6fb14130,
                0x3a96b591, 0x14], expectedOutput: '0x4bce6c5f'
      },
      {
        input: [MD5.prototype.f4, 0x26cd1e28, 0x84486c3c, 0x156745b3, 0x6fb14130,
                0x3a96b591, 0x14], expectedOutput: '0x74a69514'
      },
      {
        input: [MD5.prototype.f1, 0xdbf9ddf4, 0x508da9dd, 0xb86fb5ea, 0x2424abdb,
                0x9769d82f, 0x0d], expectedOutput: '0x7bcb5ecf'
      },
      {
        input: [MD5.prototype.f2, 0xdbf9ddf4, 0x508da9dd, 0xb86fb5ea, 0x2424abdb,
                0x9769d82f, 0x0d], expectedOutput: '0xbf112b53'
      },
      {
        input: [MD5.prototype.f3, 0xdbf9ddf4, 0x508da9dd, 0xb86fb5ea, 0x2424abdb,
                0x9769d82f, 0x0d], expectedOutput: '0x9e4f91e2'
      },
      {
        input: [MD5.prototype.f4, 0xdbf9ddf4, 0x508da9dd, 0xb86fb5ea, 0x2424abdb,
                0x9769d82f, 0x0d], expectedOutput: '0xd05504bf'
      },
      {
        input: [MD5.prototype.f1, 0x69089fd8, 0x09a39e54, 0xd0e697d6, 0xff79c472,
                0x83b46414, 0x1c], expectedOutput: '0x37df1bfa'
      },
      {
        input: [MD5.prototype.f2, 0x69089fd8, 0x09a39e54, 0xd0e697d6, 0xff79c472,
                0x83b46414, 0x1c], expectedOutput: '0x1909e810'
      },
      {
        input: [MD5.prototype.f3, 0x69089fd8, 0x09a39e54, 0xd0e697d6, 0xff79c472,
                0x83b46414, 0x1c], expectedOutput: '0xcad33b71'
      },
      {
        input: [MD5.prototype.f4, 0x69089fd8, 0x09a39e54, 0xd0e697d6, 0xff79c472,
                0x83b46414, 0x1c], expectedOutput: '0x86038113'
      },
      {
        input: [MD5.prototype.f1, 0x5eb4402e, 0x06f51d18, 0xbea5cdb6, 0xd95cf936,
                0xe9703202, 0x02], expectedOutput: '0xa63e9ab0'
      },
      {
        input: [MD5.prototype.f2, 0x5eb4402e, 0x06f51d18, 0xbea5cdb6, 0xd95cf936,
                0xe9703202, 0x02], expectedOutput: '0xc35b5c19'
      },
      {
        input: [MD5.prototype.f3, 0x5eb4402e, 0x06f51d18, 0xbea5cdb6, 0xd95cf936,
                0xe9703202, 0x02], expectedOutput: '0xabb78c3a'
      },
      {
        input: [MD5.prototype.f4, 0x5eb4402e, 0x06f51d18, 0xbea5cdb6, 0xd95cf936,
                0xe9703202, 0x02], expectedOutput: '0x88d22f97'
      },
      {
        input: [MD5.prototype.f1, 0xc1e17cad, 0xfc4595e0, 0xd93c7325, 0xc6f655d1,
                0x0093ac5b, 0x0a], expectedOutput: '0xaa2e7c54'
      },
      {
        input: [MD5.prototype.f2, 0xc1e17cad, 0xfc4595e0, 0xd93c7325, 0xc6f655d1,
                0x0093ac5b, 0x0a], expectedOutput: '0x01c9485f'
      },
      {
        input: [MD5.prototype.f3, 0xc1e17cad, 0xfc4595e0, 0xd93c7325, 0xc6f655d1,
                0x0093ac5b, 0x0a], expectedOutput: '0x0fb60878'
      },
      {
        input: [MD5.prototype.f4, 0xc1e17cad, 0xfc4595e0, 0xd93c7325, 0xc6f655d1,
                0x0093ac5b, 0x0a], expectedOutput: '0x981ce57b'
      },
      {
        input: [MD5.prototype.f1, 0xfca2c6f9, 0xfbe512f9, 0xd57792f4, 0x986b5753,
                0x900c9053, 0x0a], expectedOutput: '0x76a20c71'
      },
      {
        input: [MD5.prototype.f2, 0xfca2c6f9, 0xfbe512f9, 0xd57792f4, 0x986b5753,
                0x900c9053, 0x0a], expectedOutput: '0x8f8e18a1'
      },
      {
        input: [MD5.prototype.f3, 0xfca2c6f9, 0xfbe512f9, 0xd57792f4, 0x986b5753,
                0x900c9053, 0x0a], expectedOutput: '0xa09fbc07'
      },
      {
        input: [MD5.prototype.f4, 0xfca2c6f9, 0xfbe512f9, 0xd57792f4, 0x986b5753,
                0x900c9053, 0x0a], expectedOutput: '0xc1e269d5'
      },
      {
        input: [MD5.prototype.f1, 0x40a460e5, 0x7740370d, 0xa33e3901, 0x1ab63735,
                0xaaacaa32, 0x00], expectedOutput: '0x8e477355'
      },
      {
        input: [MD5.prototype.f2, 0x40a460e5, 0x7740370d, 0xa33e3901, 0x1ab63735,
                0xaaacaa32, 0x00], expectedOutput: '0x15998129'
      },
      {
        input: [MD5.prototype.f3, 0x40a460e5, 0x7740370d, 0xa33e3901, 0x1ab63735,
                0xaaacaa32, 0x00], expectedOutput: '0x31597b5d'
      },
      {
        input: [MD5.prototype.f4, 0x40a460e5, 0x7740370d, 0xa33e3901, 0x1ab63735,
                0xaaacaa32, 0x00], expectedOutput: '0xb70908f2'
      },
      {
        input: [MD5.prototype.f1, 0x5598eb01, 0xe5e5a47b, 0x2646ca82, 0x4a5d530a,
                0x08835eca, 0x02], expectedOutput: '0x17ca17b1'
      },
      {
        input: [MD5.prototype.f2, 0x5598eb01, 0xe5e5a47b, 0x2646ca82, 0x4a5d530a,
                0x08835eca, 0x02], expectedOutput: '0xef74edd2'
      },
      {
        input: [MD5.prototype.f3, 0x5598eb01, 0xe5e5a47b, 0x2646ca82, 0x4a5d530a,
                0x08835eca, 0x02], expectedOutput: '0x864fc376'
      },
      {
        input: [MD5.prototype.f4, 0x5598eb01, 0xe5e5a47b, 0x2646ca82, 0x4a5d530a,
                0x08835eca, 0x02], expectedOutput: '0xacdc659b'
      },
      {
        input: [MD5.prototype.f1, 0x72d3b83f, 0xe21c8062, 0x18cd1d80, 0x57bd4972,
                0x74213f2e, 0x05], expectedOutput: '0x76649021'
      },
      {
        input: [MD5.prototype.f2, 0x72d3b83f, 0xe21c8062, 0x18cd1d80, 0x57bd4972,
                0x74213f2e, 0x05], expectedOutput: '0x0c3e0a48'
      },
      {
        input: [MD5.prototype.f3, 0x72d3b83f, 0xe21c8062, 0x18cd1d80, 0x57bd4972,
                0x74213f2e, 0x05], expectedOutput: '0x6e560014'
      },
      {
        input: [MD5.prototype.f4, 0x72d3b83f, 0xe21c8062, 0x18cd1d80, 0x57bd4972,
                0x74213f2e, 0x05], expectedOutput: '0x1330dbfd'
      },
      {
        input: [MD5.prototype.f1, 0x9275c2c7, 0x239af921, 0x85dbdab2, 0x68053d4c,
                0xed858520, 0x1e], expectedOutput: '0x1601c235'
      },
      {
        input: [MD5.prototype.f2, 0x9275c2c7, 0x239af921, 0x85dbdab2, 0x68053d4c,
                0xed858520, 0x1e], expectedOutput: '0x6d108a07'
      },
      {
        input: [MD5.prototype.f3, 0x9275c2c7, 0x239af921, 0x85dbdab2, 0x68053d4c,
                0xed858520, 0x1e], expectedOutput: '0xb72ad2d2'
      },
      {
        input: [MD5.prototype.f4, 0x9275c2c7, 0x239af921, 0x85dbdab2, 0x68053d4c,
                0xed858520, 0x1e], expectedOutput: '0x5022135b'
      },
      {
        input: [MD5.prototype.f1, 0x654f5b36, 0xffd9719a, 0x12c1a19c, 0xcd0be233,
                0xe0a7bd05, 0x02], expectedOutput: '0x62c4616b'
      },
      {
        input: [MD5.prototype.f2, 0x654f5b36, 0xffd9719a, 0x12c1a19c, 0xcd0be233,
                0xe0a7bd05, 0x02], expectedOutput: '0x96db58fe'
      },
      {
        input: [MD5.prototype.f3, 0x654f5b36, 0xffd9719a, 0x12c1a19c, 0xcd0be233,
                0xe0a7bd05, 0x02], expectedOutput: '0x98029b5b'
      },
      {
        input: [MD5.prototype.f4, 0x654f5b36, 0xffd9719a, 0x12c1a19c, 0xcd0be233,
                0xe0a7bd05, 0x02], expectedOutput: '0xcca9438e'
      },
      {
        input: [MD5.prototype.f1, 0x3e5b481e, 0x6b2be1cd, 0x28c662d9, 0xa09960c7,
                0x2141365f, 0x08], expectedOutput: '0x9a0b29d5'
      },
      {
        input: [MD5.prototype.f2, 0x3e5b481e, 0x6b2be1cd, 0x28c662d9, 0xa09960c7,
                0x2141365f, 0x08], expectedOutput: '0x570d3c54'
      },
      {
        input: [MD5.prototype.f3, 0x3e5b481e, 0x6b2be1cd, 0x28c662d9, 0xa09960c7,
                0x2141365f, 0x08], expectedOutput: '0x7c8e3210'
      },
      {
        input: [MD5.prototype.f4, 0x3e5b481e, 0x6b2be1cd, 0x28c662d9, 0xa09960c7,
                0x2141365f, 0x08], expectedOutput: '0xb1478384'
      },
      {
        input: [MD5.prototype.f1, 0x09425303, 0x52e9e910, 0x389a07dd, 0x71196845,
                0x9ad3f2d3, 0x1b], expectedOutput: '0xb1975b49'
      },
      {
        input: [MD5.prototype.f2, 0x09425303, 0x52e9e910, 0x389a07dd, 0x71196845,
                0x9ad3f2d3, 0x1b], expectedOutput: '0xcacef6bb'
      },
      {
        input: [MD5.prototype.f3, 0x09425303, 0x52e9e910, 0x389a07dd, 0x71196845,
                0x9ad3f2d3, 0x1b], expectedOutput: '0x48e5ef72'
      },
      {
        input: [MD5.prototype.f4, 0x09425303, 0x52e9e910, 0x389a07dd, 0x71196845,
                0x9ad3f2d3, 0x1b], expectedOutput: '0x3f3e4b01'
      },
      {
        input: [MD5.prototype.f1, 0x5a3ab4fa, 0x327b7cea, 0x32857ef0, 0x711c9587,
                0x8278f9e8, 0x11], expectedOutput: '0x8c0a1c5d'
      },
      {
        input: [MD5.prototype.f2, 0x5a3ab4fa, 0x327b7cea, 0x32857ef0, 0x711c9587,
                0x8278f9e8, 0x11], expectedOutput: '0x8e239b84'
      },
      {
        input: [MD5.prototype.f3, 0x5a3ab4fa, 0x327b7cea, 0x32857ef0, 0x711c9587,
                0x8278f9e8, 0x11], expectedOutput: '0xbf7a1a16'
      },
      {
        input: [MD5.prototype.f4, 0x5a3ab4fa, 0x327b7cea, 0x32857ef0, 0x711c9587,
                0x8278f9e8, 0x11], expectedOutput: '0x90544f4d'
      },
      {
        input: [MD5.prototype.f1, 0xbe2f4bea, 0x5858023d, 0xd60d529c, 0x2752f7ac,
                0xafa6432a, 0x15], expectedOutput: '0x2e749e4d'
      },
      {
        input: [MD5.prototype.f2, 0xbe2f4bea, 0x5858023d, 0xd60d529c, 0x2752f7ac,
                0xafa6432a, 0x15], expectedOutput: '0x825fc88f'
      },
      {
        input: [MD5.prototype.f3, 0xbe2f4bea, 0x5858023d, 0xd60d529c, 0x2752f7ac,
                0xafa6432a, 0x15], expectedOutput: '0x1c7adde3'
      },
      {
        input: [MD5.prototype.f4, 0xbe2f4bea, 0x5858023d, 0xd60d529c, 0x2752f7ac,
                0xafa6432a, 0x15], expectedOutput: '0x57479af9'
      },
      {
        input: [MD5.prototype.f1, 0x2d9e9145, 0xbcaf178a, 0x04079ad5, 0xb0064458,
                0xaa02a29d, 0x18], expectedOutput: '0x6f8ac010'
      },
      {
        input: [MD5.prototype.f2, 0x2d9e9145, 0xbcaf178a, 0x04079ad5, 0xb0064458,
                0xaa02a29d, 0x18], expectedOutput: '0x2c3ac05c'
      },
      {
        input: [MD5.prototype.f3, 0x2d9e9145, 0xbcaf178a, 0x04079ad5, 0xb0064458,
                0xaa02a29d, 0x18], expectedOutput: '0xa68f6786'
      },
      {
        input: [MD5.prototype.f4, 0x2d9e9145, 0xbcaf178a, 0x04079ad5, 0xb0064458,
                0xaa02a29d, 0x18], expectedOutput: '0x1982b0e3'
      },
      {
        input: [MD5.prototype.f1, 0xcbd6cba1, 0x837b7c0e, 0x4815c0aa, 0x9c5f9fed,
                0x6236345b, 0x18], expectedOutput: '0x6ac59ed1'
      },
      {
        input: [MD5.prototype.f2, 0xcbd6cba1, 0x837b7c0e, 0x4815c0aa, 0x9c5f9fed,
                0x6236345b, 0x18], expectedOutput: '0x8e69e46a'
      },
      {
        input: [MD5.prototype.f3, 0xcbd6cba1, 0x837b7c0e, 0x4815c0aa, 0x9c5f9fed,
                0x6236345b, 0x18], expectedOutput: '0xc900ba31'
      },
      {
        input: [MD5.prototype.f4, 0xcbd6cba1, 0x837b7c0e, 0x4815c0aa, 0x9c5f9fed,
                0x6236345b, 0x18], expectedOutput: '0x345577ca'
      },
      {
        input: [MD5.prototype.f1, 0x443e3ea7, 0x59ee41e0, 0xc6248ff0, 0xd643325b,
                0xca96edb5, 0x15], expectedOutput: '0x64e8e12c'
      },
      {
        input: [MD5.prototype.f2, 0x443e3ea7, 0x59ee41e0, 0xc6248ff0, 0xd643325b,
                0xca96edb5, 0x15], expectedOutput: '0xa17a2957'
      },
      {
        input: [MD5.prototype.f3, 0x443e3ea7, 0x59ee41e0, 0xc6248ff0, 0xd643325b,
                0xca96edb5, 0x15], expectedOutput: '0x6ed94dc5'
      },
      {
        input: [MD5.prototype.f4, 0x443e3ea7, 0x59ee41e0, 0xc6248ff0, 0xd643325b,
                0xca96edb5, 0x15], expectedOutput: '0x280817cd'
      },
      {
        input: [MD5.prototype.f1, 0xc51f956a, 0x022856c9, 0x2340cfe4, 0x01642113,
                0x9e90547a, 0x1a], expectedOutput: '0xdbc4280f'
      },
      {
        input: [MD5.prototype.f2, 0xc51f956a, 0x022856c9, 0x2340cfe4, 0x01642113,
                0x9e90547a, 0x1a], expectedOutput: '0x283f99ac'
      },
      {
        input: [MD5.prototype.f3, 0xc51f956a, 0x022856c9, 0x2340cfe4, 0x01642113,
                0x9e90547a, 0x1a], expectedOutput: '0x8c374951'
      },
      {
        input: [MD5.prototype.f4, 0xc51f956a, 0x022856c9, 0x2340cfe4, 0x01642113,
                0x9e90547a, 0x1a], expectedOutput: '0xb72f02b4'
      },
      {
        input: [MD5.prototype.f1, 0x85c15dd0, 0x8050574a, 0xfa15bada, 0xa750de7f,
                0x217634e0, 0x17], expectedOutput: '0x17f77b60'
      },
      {
        input: [MD5.prototype.f2, 0x85c15dd0, 0x8050574a, 0xfa15bada, 0xa750de7f,
                0x217634e0, 0x17], expectedOutput: '0x3d901dce'
      },
      {
        input: [MD5.prototype.f3, 0x85c15dd0, 0x8050574a, 0xfa15bada, 0xa750de7f,
                0x217634e0, 0x17], expectedOutput: '0xd0127dad'
      },
      {
        input: [MD5.prototype.f4, 0x85c15dd0, 0x8050574a, 0xfa15bada, 0xa750de7f,
                0x217634e0, 0x17], expectedOutput: '0x60b56879'
      },
      {
        input: [MD5.prototype.f1, 0xbc8abb42, 0x2a5a1b0f, 0xc8872a06, 0xff1fd2af,
                0x67b9fa52, 0x14], expectedOutput: '0x2dfa2fd7'
      },
      {
        input: [MD5.prototype.f2, 0xbc8abb42, 0x2a5a1b0f, 0xc8872a06, 0xff1fd2af,
                0x67b9fa52, 0x14], expectedOutput: '0x248f08fd'
      },
      {
        input: [MD5.prototype.f3, 0xbc8abb42, 0x2a5a1b0f, 0xc8872a06, 0xff1fd2af,
                0x67b9fa52, 0x14], expectedOutput: '0xbdfe3b88'
      },
      {
        input: [MD5.prototype.f4, 0xbc8abb42, 0x2a5a1b0f, 0xc8872a06, 0xff1fd2af,
                0x67b9fa52, 0x14], expectedOutput: '0xd92a872b'
      },
      {
        input: [MD5.prototype.f1, 0x26e04445, 0xd0475778, 0x6b8b89e0, 0x9f869b45,
                0x4cc98cc5, 0x14], expectedOutput: '0x77438a4d'
      },
      {
        input: [MD5.prototype.f2, 0x26e04445, 0xd0475778, 0x6b8b89e0, 0x9f869b45,
                0x4cc98cc5, 0x14], expectedOutput: '0x1eed9306'
      },
      {
        input: [MD5.prototype.f3, 0x26e04445, 0xd0475778, 0x6b8b89e0, 0x9f869b45,
                0x4cc98cc5, 0x14], expectedOutput: '0x3ec0d6b9'
      },
      {
        input: [MD5.prototype.f4, 0x26e04445, 0xd0475778, 0x6b8b89e0, 0x9f869b45,
                0x4cc98cc5, 0x14], expectedOutput: '0xc2885164'
      },
      {
        input: [MD5.prototype.f1, 0x7078741e, 0x62d7316e, 0x4ba61d6a, 0x8aa21e43,
                0x7a1382ee, 0x0d], expectedOutput: '0xa5a62814'
      },
      {
        input: [MD5.prototype.f2, 0x7078741e, 0x62d7316e, 0x4ba61d6a, 0x8aa21e43,
                0x7a1382ee, 0x0d], expectedOutput: '0xa3e5f730'
      },
      {
        input: [MD5.prototype.f3, 0x7078741e, 0x62d7316e, 0x4ba61d6a, 0x8aa21e43,
                0x7a1382ee, 0x0d], expectedOutput: '0x4801a339'
      },
      {
        input: [MD5.prototype.f4, 0x7078741e, 0x62d7316e, 0x4ba61d6a, 0x8aa21e43,
                0x7a1382ee, 0x0d], expectedOutput: '0x1f4b364e'
      },
      {
        input: [MD5.prototype.f1, 0xdaf77315, 0x5426c000, 0xb0c84538, 0x8de236b5,
                0x3eaa4c98, 0x17], expectedOutput: '0x8580711b'
      },
      {
        input: [MD5.prototype.f2, 0xdaf77315, 0x5426c000, 0xb0c84538, 0x8de236b5,
                0x3eaa4c98, 0x17], expectedOutput: '0xaecda600'
      },
      {
        input: [MD5.prototype.f3, 0xdaf77315, 0x5426c000, 0xb0c84538, 0x8de236b5,
                0x3eaa4c98, 0x17], expectedOutput: '0xf1681739'
      },
      {
        input: [MD5.prototype.f4, 0xdaf77315, 0x5426c000, 0xb0c84538, 0x8de236b5,
                0x3eaa4c98, 0x17], expectedOutput: '0x64170ca6'
      },
      {
        input: [MD5.prototype.f1, 0x4b77395d, 0xa9c58abc, 0xd91ddae2, 0xdb991db4,
                0x3a20d171, 0x02], expectedOutput: '0x2c9c3475'
      },
      {
        input: [MD5.prototype.f2, 0x4b77395d, 0xa9c58abc, 0xd91ddae2, 0xdb991db4,
                0x3a20d171, 0x02], expectedOutput: '0xe63ce1cc'
      },
      {
        input: [MD5.prototype.f3, 0x4b77395d, 0xa9c58abc, 0xd91ddae2, 0xdb991db4,
                0x3a20d171, 0x02], expectedOutput: '0x6d2aed9c'
      },
      {
        input: [MD5.prototype.f4, 0x4b77395d, 0xa9c58abc, 0xd91ddae2, 0xdb991db4,
                0x3a20d171, 0x02], expectedOutput: '0x940e766b'
      },
      {
        input: [MD5.prototype.f1, 0x09626470, 0x48470cb0, 0x7081a4f9, 0xb5fa3df0,
                0x0490dce7, 0x15], expectedOutput: '0x3127823e'
      },
      {
        input: [MD5.prototype.f2, 0x09626470, 0x48470cb0, 0x7081a4f9, 0xb5fa3df0,
                0x0490dce7, 0x15], expectedOutput: '0x0a50d389'
      },
      {
        input: [MD5.prototype.f3, 0x09626470, 0x48470cb0, 0x7081a4f9, 0xb5fa3df0,
                0x0490dce7, 0x15], expectedOutput: '0x2a5a72aa'
      },
      {
        input: [MD5.prototype.f4, 0x09626470, 0x48470cb0, 0x7081a4f9, 0xb5fa3df0,
                0x0490dce7, 0x15], expectedOutput: '0xbbf023e5'
      },
      {
        input: [MD5.prototype.f1, 0x921f4e21, 0xa2cc3f20, 0x77063d15, 0x8d84b646,
                0x80327dfe, 0x0e], expectedOutput: '0x45258f75'
      },
      {
        input: [MD5.prototype.f2, 0x921f4e21, 0xa2cc3f20, 0x77063d15, 0x8d84b646,
                0x80327dfe, 0x0e], expectedOutput: '0xa5984056'
      },
      {
        input: [MD5.prototype.f3, 0x921f4e21, 0xa2cc3f20, 0x77063d15, 0x8d84b646,
                0x80327dfe, 0x0e], expectedOutput: '0xc2f0d9c8'
      },
      {
        input: [MD5.prototype.f4, 0x921f4e21, 0xa2cc3f20, 0x77063d15, 0x8d84b646,
                0x80327dfe, 0x0e], expectedOutput: '0x667f2532'
      },
      {
        input: [MD5.prototype.f1, 0xa4d7e8bd, 0x7aa867c5, 0xcbc9c9ac, 0x280be95c,
                0x9165208b, 0x17], expectedOutput: '0xece8cc2e'
      },
      {
        input: [MD5.prototype.f2, 0xa4d7e8bd, 0x7aa867c5, 0xcbc9c9ac, 0x280be95c,
                0x9165208b, 0x17], expectedOutput: '0x10b96a7a'
      },
      {
        input: [MD5.prototype.f3, 0xa4d7e8bd, 0x7aa867c5, 0xcbc9c9ac, 0x280be95c,
                0x9165208b, 0x17], expectedOutput: '0xb9903b6d'
      },
      {
        input: [MD5.prototype.f4, 0xa4d7e8bd, 0x7aa867c5, 0xcbc9c9ac, 0x280be95c,
                0x9165208b, 0x17], expectedOutput: '0x445da128'
      },
      {
        input: [MD5.prototype.f1, 0x46391b47, 0x87c66b99, 0x646f838d, 0xd0cc3428,
                0x789a78af, 0x03], expectedOutput: '0x20d3c891'
      },
      {
        input: [MD5.prototype.f2, 0x46391b47, 0x87c66b99, 0x646f838d, 0xd0cc3428,
                0x789a78af, 0x03], expectedOutput: '0xa5a027b4'
      },
      {
        input: [MD5.prototype.f3, 0x46391b47, 0x87c66b99, 0x646f838d, 0xd0cc3428,
                0x789a78af, 0x03], expectedOutput: '0x1991ed30'
      },
      {
        input: [MD5.prototype.f4, 0x46391b47, 0x87c66b99, 0x646f838d, 0xd0cc3428,
                0x789a78af, 0x03], expectedOutput: '0xdb264ddd'
      },
      {
        input: [MD5.prototype.f1, 0xec1e4e61, 0x067d846e, 0x6821c42f, 0xd0d3ba0a,
                0xb1546041, 0x05], expectedOutput: '0xc94b1e7b'
      },
      {
        input: [MD5.prototype.f2, 0xec1e4e61, 0x067d846e, 0x6821c42f, 0xd0d3ba0a,
                0xb1546041, 0x05], expectedOutput: '0xc30bdea6'
      },
      {
        input: [MD5.prototype.f3, 0xec1e4e61, 0x067d846e, 0x6821c42f, 0xd0d3ba0a,
                0xb1546041, 0x05], expectedOutput: '0x86d2a219'
      },
      {
        input: [MD5.prototype.f4, 0xec1e4e61, 0x067d846e, 0x6821c42f, 0xd0d3ba0a,
                0xb1546041, 0x05], expectedOutput: '0xa05392ca'
      },
      {
        input: [MD5.prototype.f1, 0x944c91e5, 0x4c0ce609, 0xfb9b6ddc, 0xd67f0959,
                0x319bae0f, 0x17], expectedOutput: '0xf25d17df'
      },
      {
        input: [MD5.prototype.f2, 0x944c91e5, 0x4c0ce609, 0xfb9b6ddc, 0xd67f0959,
                0x319bae0f, 0x17], expectedOutput: '0x8ca6a05b'
      },
      {
        input: [MD5.prototype.f3, 0x944c91e5, 0x4c0ce609, 0xfb9b6ddc, 0xd67f0959,
                0x319bae0f, 0x17], expectedOutput: '0x8c20ce6a'
      },
      {
        input: [MD5.prototype.f4, 0x944c91e5, 0x4c0ce609, 0xfb9b6ddc, 0xd67f0959,
                0x319bae0f, 0x17], expectedOutput: '0xffbae5f6'
      },
      {
        input: [MD5.prototype.f1, 0x2d76eaeb, 0x10deca4b, 0x92a1c346, 0x6479aa58,
                0x91d255f6, 0x10], expectedOutput: '0x3411fe36'
      },
      {
        input: [MD5.prototype.f2, 0x2d76eaeb, 0x10deca4b, 0x92a1c346, 0x6479aa58,
                0x91d255f6, 0x10], expectedOutput: '0x1d0e1c6d'
      },
      {
        input: [MD5.prototype.f3, 0x2d76eaeb, 0x10deca4b, 0x92a1c346, 0x6479aa58,
                0x91d255f6, 0x10], expectedOutput: '0xf5156f9a'
      },
      {
        input: [MD5.prototype.f4, 0x2d76eaeb, 0x10deca4b, 0x92a1c346, 0x6479aa58,
                0x91d255f6, 0x10], expectedOutput: '0x6e699313'
      },
      {
        input: [MD5.prototype.f1, 0xaa02cf9b, 0x95db9d7e, 0xb87fc742, 0xd282caf4,
                0x7b95c8da, 0x1b], expectedOutput: '0x559b407f'
      },
      {
        input: [MD5.prototype.f2, 0xaa02cf9b, 0x95db9d7e, 0xb87fc742, 0xd282caf4,
                0x7b95c8da, 0x1b], expectedOutput: '0xf4d05ead'
      },
      {
        input: [MD5.prototype.f3, 0xaa02cf9b, 0x95db9d7e, 0xb87fc742, 0xd282caf4,
                0x7b95c8da, 0x1b], expectedOutput: '0x7f0196c7'
      },
      {
        input: [MD5.prototype.f4, 0xaa02cf9b, 0x95db9d7e, 0xb87fc742, 0xd282caf4,
                0x7b95c8da, 0x1b], expectedOutput: '0x27346613'
      },
      {
        input: [MD5.prototype.f1, 0x1c52d425, 0x7aad2429, 0x5149484f, 0xceeec7f3,
                0xdc95315c, 0x09], expectedOutput: '0xe23fddc3'
      },
      {
        input: [MD5.prototype.f2, 0x1c52d425, 0x7aad2429, 0x5149484f, 0xceeec7f3,
                0xdc95315c, 0x09], expectedOutput: '0xa4d080d2'
      },
      {
        input: [MD5.prototype.f3, 0x1c52d425, 0x7aad2429, 0x5149484f, 0xceeec7f3,
                0xdc95315c, 0x09], expectedOutput: '0x600f51e4'
      },
      {
        input: [MD5.prototype.f4, 0x1c52d425, 0x7aad2429, 0x5149484f, 0xceeec7f3,
                0xdc95315c, 0x09], expectedOutput: '0x33a0ea70'
      },
      {
        input: [MD5.prototype.f1, 0x815b6ca6, 0x8ffcf134, 0x306322de, 0xeb548d3e,
                0x5034a407, 0x15], expectedOutput: '0x29632f3b'
      },
      {
        input: [MD5.prototype.f2, 0x815b6ca6, 0x8ffcf134, 0x306322de, 0xeb548d3e,
                0x5034a407, 0x15], expectedOutput: '0x242a922a'
      },
      {
        input: [MD5.prototype.f3, 0x815b6ca6, 0x8ffcf134, 0x306322de, 0xeb548d3e,
                0x5034a407, 0x15], expectedOutput: '0x8021bca1'
      },
      {
        input: [MD5.prototype.f4, 0x815b6ca6, 0x8ffcf134, 0x306322de, 0xeb548d3e,
                0x5034a407, 0x15], expectedOutput: '0xcb0d16d0'
      },
      {
        input: [MD5.prototype.f1, 0x74f5e418, 0xfe508b15, 0x706af714, 0x74619f78,
                0x92963f2e, 0x10], expectedOutput: '0xb9130302'
      },
      {
        input: [MD5.prototype.f2, 0x74f5e418, 0xfe508b15, 0x706af714, 0x74619f78,
                0x92963f2e, 0x10], expectedOutput: '0x0cab06ec'
      },
      {
        input: [MD5.prototype.f3, 0x74f5e418, 0xfe508b15, 0x706af714, 0x74619f78,
                0x92963f2e, 0x10], expectedOutput: '0x050f8cfd'
      },
      {
        input: [MD5.prototype.f4, 0x74f5e418, 0xfe508b15, 0x706af714, 0x74619f78,
                0x92963f2e, 0x10], expectedOutput: '0x3e1a2255'
      },
      {
        input: [MD5.prototype.f1, 0x26c0c41f, 0x5e76f468, 0x10428e1b, 0x539b5703,
                0xc04ab055, 0x00], expectedOutput: '0x574defe7'
      },
      {
        input: [MD5.prototype.f2, 0x26c0c41f, 0x5e76f468, 0x10428e1b, 0x539b5703,
                0xc04ab055, 0x00], expectedOutput: '0x97d544f4'
      },
      {
        input: [MD5.prototype.f3, 0x26c0c41f, 0x5e76f468, 0x10428e1b, 0x539b5703,
                0xc04ab055, 0x00], expectedOutput: '0x6331964c'
      },
      {
        input: [MD5.prototype.f4, 0x26c0c41f, 0x5e76f468, 0x10428e1b, 0x539b5703,
                0xc04ab055, 0x00], expectedOutput: '0x33b6dbc3'
      },
      {
        input: [MD5.prototype.f1, 0x8d37815f, 0x301fcdc0, 0x62f53ea2, 0xdb565d64,
                0xfd6971bb, 0x01], expectedOutput: '0x1c0bed3c'
      },
      {
        input: [MD5.prototype.f2, 0x8d37815f, 0x301fcdc0, 0x62f53ea2, 0xdb565d64,
                0xfd6971bb, 0x01], expectedOutput: '0xa6d09379'
      },
      {
        input: [MD5.prototype.f3, 0x8d37815f, 0x301fcdc0, 0x62f53ea2, 0xdb565d64,
                0xfd6971bb, 0x01], expectedOutput: '0x58db1000'
      },
      {
        input: [MD5.prototype.f4, 0x8d37815f, 0x301fcdc0, 0x62f53ea2, 0xdb565d64,
                0xfd6971bb, 0x01], expectedOutput: '0xf1f756e7'
      },
      {
        input: [MD5.prototype.f1, 0xaac01d54, 0xed6a0acd, 0x046ec9cd, 0x76d12e56,
                0x54b4735f, 0x15], expectedOutput: '0x9facd8c4'
      },
      {
        input: [MD5.prototype.f2, 0xaac01d54, 0xed6a0acd, 0x046ec9cd, 0x76d12e56,
                0x54b4735f, 0x15], expectedOutput: '0x7d768738'
      },
      {
        input: [MD5.prototype.f3, 0xaac01d54, 0xed6a0acd, 0x046ec9cd, 0x76d12e56,
                0x54b4735f, 0x15], expectedOutput: '0xae9df41c'
      },
      {
        input: [MD5.prototype.f4, 0xaac01d54, 0xed6a0acd, 0x046ec9cd, 0x76d12e56,
                0x54b4735f, 0x15], expectedOutput: '0x47e71961'
      },
      {
        input: [MD5.prototype.f1, 0x6df42bb1, 0x1e6a5d9c, 0x8a3bbfca, 0xd3940869,
                0x639c61f5, 0x05], expectedOutput: '0xc83fcf8f'
      },
      {
        input: [MD5.prototype.f2, 0x6df42bb1, 0x1e6a5d9c, 0x8a3bbfca, 0xd3940869,
                0x639c61f5, 0x05], expectedOutput: '0x95f403b9'
      },
      {
        input: [MD5.prototype.f3, 0x6df42bb1, 0x1e6a5d9c, 0x8a3bbfca, 0xd3940869,
                0x639c61f5, 0x05], expectedOutput: '0x49395a3f'
      },
      {
        input: [MD5.prototype.f4, 0x6df42bb1, 0x1e6a5d9c, 0x8a3bbfca, 0xd3940869,
                0x639c61f5, 0x05], expectedOutput: '0xda841cec'
      },
      {
        input: [MD5.prototype.f1, 0xf0683791, 0x80441daa, 0x2aabf636, 0xcd874863,
                0xa18c5166, 0x1b], expectedOutput: '0x573fdc94'
      },
      {
        input: [MD5.prototype.f2, 0xf0683791, 0x80441daa, 0x2aabf636, 0xcd874863,
                0xa18c5166, 0x1b], expectedOutput: '0xe9e527e3'
      },
      {
        input: [MD5.prototype.f3, 0xf0683791, 0x80441daa, 0x2aabf636, 0xcd874863,
                0xa18c5166, 0x1b], expectedOutput: '0x380f0711'
      },
      {
        input: [MD5.prototype.f4, 0xf0683791, 0x80441daa, 0x2aabf636, 0xcd874863,
                0xa18c5166, 0x1b], expectedOutput: '0x799a7c3d'
      },
      {
        input: [MD5.prototype.f1, 0x9ec870a9, 0x370164d1, 0xbf6e9257, 0xc7dc1883,
                0x44bd1298, 0x1c], expectedOutput: '0x84b77e8a'
      },
      {
        input: [MD5.prototype.f2, 0x9ec870a9, 0x370164d1, 0xbf6e9257, 0xc7dc1883,
                0x44bd1298, 0x1c], expectedOutput: '0x992be532'
      },
      {
        input: [MD5.prototype.f3, 0x9ec870a9, 0x370164d1, 0xbf6e9257, 0xc7dc1883,
                0x44bd1298, 0x1c], expectedOutput: '0x9a34fbe5'
      },
      {
        input: [MD5.prototype.f4, 0x9ec870a9, 0x370164d1, 0xbf6e9257, 0xc7dc1883,
                0x44bd1298, 0x1c], expectedOutput: '0xed3e945f'
      },
      {
        input: [MD5.prototype.f1, 0xf2eec48c, 0xf1937a15, 0x38613c70, 0xdb9d32da,
                0xd76df469, 0x13], expectedOutput: '0x800b9d64'
      },
      {
        input: [MD5.prototype.f2, 0xf2eec48c, 0xf1937a15, 0x38613c70, 0xdb9d32da,
                0xd76df469, 0x13], expectedOutput: '0xaac15c84'
      },
      {
        input: [MD5.prototype.f3, 0xf2eec48c, 0xf1937a15, 0x38613c70, 0xdb9d32da,
                0xd76df469, 0x13], expectedOutput: '0x5f3a6076'
      },
      {
        input: [MD5.prototype.f4, 0xf2eec48c, 0xf1937a15, 0x38613c70, 0xdb9d32da,
                0xd76df469, 0x13], expectedOutput: '0xd3683990'
      },
      {
        input: [MD5.prototype.f1, 0x88b890f0, 0xdfcc75a2, 0x84a35896, 0xddfeb84a,
                0x0a196ea9, 0x07], expectedOutput: '0xa238a72d'
      },
      {
        input: [MD5.prototype.f2, 0x88b890f0, 0xdfcc75a2, 0x84a35896, 0xddfeb84a,
                0x0a196ea9, 0x07], expectedOutput: '0x2f848d5a'
      },
      {
        input: [MD5.prototype.f3, 0x88b890f0, 0xdfcc75a2, 0x84a35896, 0xddfeb84a,
                0x0a196ea9, 0x07], expectedOutput: '0x9197012e'
      },
      {
        input: [MD5.prototype.f4, 0x88b890f0, 0xdfcc75a2, 0x84a35896, 0xddfeb84a,
                0x0a196ea9, 0x07], expectedOutput: '0xffe3d2a9'
      },
    ],
    testFunction: function(i) {
      return MD5.prototype.dwordToHex(
          MD5.prototype.step(i[0], i[1], i[2], i[3], i[4], i[5], i[6]));
    }
  },

  {
    desc: 'All sample TRANSFORM inputs produce the expected change in state.',
    dataProvider: [
      {
        input: ['0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0'],
        expectedOutput: '0x031f1dac,0x6ea58ed0,0x1fab67b7,0x74317791'
      },
      {
        input: ['0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63'],
        expectedOutput: '0x9144d9ca,0xd901e4c9,0x72fc5b38,0x625ff51e'
      },
      {
        input: ['61,68,206,166,56,60,126,235,44,110,123,228,246,30,90,195,253,240,27,160,116,102,88,114,67,2,225,93,12,136,80,73,204,31,240,4,91,110,239,135,220,107,108,210,137,198,149,134,182,177,38,42,23,126,156,90,128,125,183,141,5,8,214,209'],
        expectedOutput: '0xcfae65b8,0xf50d92fa,0x8d1cc108,0x31324958'
      },
      {
        input: ['39,198,213,130,52,197,9,16,48,117,227,185,59,120,63,241,41,101,27,64,227,184,155,100,53,82,241,59,90,199,12,129,142,226,3,194,167,13,211,215,130,182,144,190,46,207,175,88,52,203,152,23,131,51,123,184,134,108,243,224,52,0,98,194'],
        expectedOutput: '0x401991c3,0x423ac325,0xc3b861e2,0xa5df0a79'
      },
      {
        input: ['226,101,132,137,114,87,96,245,13,240,179,60,191,98,148,243,45,44,10,176,96,134,105,230,242,92,198,38,92,40,232,62,142,109,199,0,196,39,245,210,23,168,14,214,11,162,201,56,206,212,233,46,90,82,20,76,174,219,115,11,3,91,73,145'],
        expectedOutput: '0xa4831375,0xf29e391c,0xf099dbb4,0xdc6d6612'
      },
      {
        input: ['200,17,146,141,56,135,95,80,48,109,38,59,15,240,115,221,196,92,12,30,174,32,106,93,251,221,104,255,57,177,144,1,194,34,142,251,170,237,75,218,90,113,21,105,97,136,71,37,229,83,67,147,115,174,240,111,139,88,110,196,10,254,198,204'],
        expectedOutput: '0xa37dba39,0xca6d415d,0xb0c2dbd9,0x02db9ca4'
      },
      {
        input: ['33,84,199,203,66,18,165,156,132,186,6,229,66,77,11,39,160,78,187,19,252,171,130,136,4,240,76,14,239,18,218,16,103,162,219,169,180,128,69,56,58,75,30,124,152,41,164,56,119,95,76,116,10,206,252,14,191,72,28,174,91,247,190,194'],
        expectedOutput: '0x637f41bb,0x7adc2e1b,0xb2fec17e,0xa240f747'
      },
      {
        input: ['153,153,107,77,25,176,134,83,252,164,207,148,205,115,205,68,210,25,184,221,231,180,235,166,253,8,84,88,255,18,26,152,171,133,229,196,53,107,23,49,15,231,198,220,90,147,33,45,172,217,10,147,142,245,58,139,253,142,227,252,161,253,148,76'],
        expectedOutput: '0xa643635a,0xb2078e69,0x41d7a95d,0x1f41bbc2'
      },
      {
        input: ['130,122,17,183,229,40,233,245,15,175,209,106,66,242,151,238,204,161,129,90,150,187,229,148,74,200,144,235,197,37,55,71,159,72,254,132,113,231,121,128,150,75,234,216,61,129,198,9,34,72,99,185,3,72,77,77,16,221,56,213,2,112,28,161'],
        expectedOutput: '0xf367a770,0xd62ab091,0x2b9625f6,0x33960abf'
      },
      {
        input: ['184,27,38,41,2,159,170,153,234,148,113,40,22,56,49,56,128,149,241,131,221,62,209,238,28,9,195,30,121,224,192,50,251,230,91,253,133,5,150,112,154,8,152,176,64,201,232,192,94,218,67,60,24,20,42,52,30,237,83,151,205,19,201,200'],
        expectedOutput: '0x4c58290b,0x8fe05936,0xd6bff9aa,0xff2dfe88'
      },
      {
        input: ['249,37,198,126,42,92,238,196,100,134,116,164,80,93,100,174,55,168,234,79,188,20,132,218,2,215,114,207,234,59,152,227,96,94,97,139,186,80,79,31,214,196,195,38,33,40,213,88,208,191,167,140,212,43,103,214,2,217,165,236,20,61,207,117'],
        expectedOutput: '0x2f17f41b,0xb9dea1c0,0x904d57ff,0x6a01d22d'
      },
      {
        input: ['155,49,0,86,129,79,117,87,19,56,126,52,96,83,140,48,18,52,189,230,95,36,188,98,253,98,78,17,159,30,134,59,79,134,145,208,214,6,39,233,62,165,30,159,248,170,207,11,222,140,241,62,176,174,160,173,16,238,191,175,12,69,234,91'],
        expectedOutput: '0x878aa12e,0x28628013,0x5d75bd84,0x4e0b0518'
      },
      {
        input: ['204,123,43,162,129,83,139,192,248,169,95,241,84,46,252,50,187,237,112,107,155,16,25,171,255,216,91,11,29,69,103,233,193,146,139,66,229,23,2,222,192,97,207,20,144,203,71,75,184,183,182,84,200,207,255,199,167,90,210,197,160,57,174,97'],
        expectedOutput: '0xf2bd39dc,0x792aa77c,0xeaff59db,0xc4f49d77'
      },
      {
        input: ['204,58,163,177,81,166,143,17,7,94,38,151,41,109,226,226,36,153,54,236,104,53,179,16,144,134,213,48,191,131,145,139,189,52,61,14,218,204,32,226,43,70,121,84,179,92,54,215,245,108,196,93,162,119,109,50,253,66,98,189,198,243,72,131'],
        expectedOutput: '0xad803b4d,0x641c7149,0x4a89b44a,0x87e3b8fb'
      },
      {
        input: ['39,133,146,2,82,178,228,125,248,93,209,171,185,8,130,174,116,70,12,22,190,121,72,187,188,170,120,130,157,193,5,197,70,151,199,152,73,171,21,65,8,231,236,194,239,111,112,99,181,124,122,115,246,194,47,178,109,167,52,10,104,57,207,175'],
        expectedOutput: '0x42b037e0,0xc202b675,0x29b77ad0,0xf0b40d6a'
      },
      {
        input: ['209,150,71,26,65,93,92,74,68,72,12,51,183,124,150,109,249,16,224,239,211,15,161,64,183,213,74,31,14,26,206,223,176,22,250,242,115,86,60,183,158,72,234,86,196,128,195,189,145,163,172,100,179,77,164,106,34,238,137,49,8,88,16,185'],
        expectedOutput: '0xc8ec9719,0x49823003,0x138f7a51,0x05fb4a7e'
      },
      {
        input: ['110,10,171,225,96,231,152,255,47,130,85,243,2,24,177,147,187,93,247,110,171,155,216,205,138,98,254,146,186,15,75,40,25,246,9,122,221,161,121,12,35,206,0,37,230,177,185,161,14,176,16,185,76,232,135,214,74,133,104,4,148,180,44,174'],
        expectedOutput: '0x67792faa,0x9af4c1d9,0xdb2a6b53,0x2e356571'
      },
      {
        input: ['170,53,40,136,214,161,148,249,111,148,31,85,69,216,246,84,136,6,13,212,239,148,170,57,26,19,62,174,199,106,92,113,160,132,249,118,37,142,112,148,34,143,233,104,103,224,188,239,230,201,196,213,94,110,15,120,129,77,38,72,183,131,186,87'],
        expectedOutput: '0x32980976,0xc175bbb5,0x6426c91b,0xa48df07f'
      },
      {
        input: ['7,179,206,45,65,62,193,100,205,171,204,52,139,136,35,113,81,231,71,175,86,86,39,215,163,78,32,90,209,218,178,216,141,128,5,207,190,199,51,139,114,255,191,253,135,226,110,216,202,181,136,32,11,175,247,174,253,23,9,206,241,187,167,127'],
        expectedOutput: '0x6beb9b65,0x47567c9f,0x99973106,0x81cbb6f3'
      },
      {
        input: ['59,172,78,249,115,129,132,229,128,67,226,7,37,81,223,239,6,103,15,18,23,7,192,20,30,201,227,16,132,138,143,191,54,221,184,170,94,60,143,222,127,114,229,165,195,196,148,201,44,164,219,67,171,156,87,201,101,58,217,234,196,104,169,251'],
        expectedOutput: '0x904d464f,0xa7f74e40,0x5018103b,0x5340c3e2'
      },
      {
        input: ['69,98,165,163,158,52,129,30,166,102,195,105,43,87,51,87,251,14,154,166,170,241,112,16,44,73,250,240,178,163,235,247,5,144,155,164,197,28,194,107,131,133,213,174,220,8,5,216,22,159,126,193,144,238,209,188,56,203,173,234,110,152,225,116'],
        expectedOutput: '0x0c176b02,0x4aac7d1a,0x00e1f6f0,0xcaa7c512'
      },
      {
        input: ['41,124,24,238,153,218,89,28,95,46,202,59,54,207,19,77,110,146,14,254,128,223,187,184,170,104,162,24,0,132,140,41,0,164,23,153,126,113,181,221,159,127,25,214,78,44,35,188,190,49,187,63,16,118,247,186,222,154,210,222,30,95,8,30'],
        expectedOutput: '0xdc428a2a,0xa95b822a,0x4bbeeba0,0x9e41dd88'
      },
      {
        input: ['3,31,184,130,144,109,95,48,237,120,6,59,165,41,248,99,90,179,162,106,41,154,36,7,52,246,229,82,85,237,112,89,13,40,219,157,150,58,205,131,179,211,190,88,252,182,187,86,105,94,192,146,248,228,153,44,219,127,126,48,108,238,137,121'],
        expectedOutput: '0xb3f79626,0x67c21d1d,0xa4129420,0x57dec7ff'
      },
      {
        input: ['23,100,23,173,159,228,48,82,184,238,170,180,165,101,11,14,195,203,161,187,176,58,231,139,185,101,187,38,84,69,159,107,169,182,24,72,155,72,154,83,54,68,7,219,170,18,234,109,222,139,41,142,197,16,25,127,118,212,165,202,25,68,53,195'],
        expectedOutput: '0xf5ddeed9,0x7553f558,0x1dba8060,0x61370ec6'
      },
      {
        input: ['251,77,11,150,149,166,233,203,234,240,167,148,3,145,2,225,28,43,111,225,59,136,96,177,92,5,123,118,74,176,57,69,253,68,219,146,234,196,94,213,180,5,105,183,150,107,152,178,150,7,147,210,143,244,131,236,249,255,98,67,175,155,136,173'],
        expectedOutput: '0x2e4dbf41,0xe4c44f06,0x55b7c090,0x66a03374'
      },
      {
        input: ['223,99,63,202,39,157,159,220,162,8,147,56,116,44,234,10,51,126,220,195,114,96,175,107,95,17,175,14,172,55,187,139,155,251,85,194,152,244,158,59,253,50,115,113,94,94,123,145,220,88,84,78,184,3,185,23,20,104,37,192,160,225,76,59'],
        expectedOutput: '0xfddbb483,0xe0a8b4c5,0x5e258229,0x52f8ea08'
      },
      {
        input: ['220,161,253,116,150,156,175,147,206,35,4,44,129,127,189,93,215,18,171,143,21,100,166,42,205,204,234,109,173,54,168,137,216,165,253,110,65,173,1,15,208,5,59,81,132,249,174,92,11,89,235,32,189,146,74,138,94,53,247,11,107,159,148,67'],
        expectedOutput: '0x040ad9ed,0xd9abfcf2,0xdfc5182f,0x9c87f6f6'
      },
      {
        input: ['69,145,177,134,62,178,150,14,183,209,95,60,202,13,152,213,102,131,246,36,21,64,174,115,117,166,126,225,69,18,36,138,164,214,17,226,136,167,241,64,120,80,124,67,94,20,24,196,151,14,232,173,79,151,32,196,61,159,165,130,177,202,13,85'],
        expectedOutput: '0x6a29a999,0x498f4a1d,0x2ed6eb4e,0x5bca4013'
      },
      {
        input: ['160,30,56,40,197,41,104,61,121,228,128,215,248,153,156,144,167,132,61,246,27,93,187,88,252,96,219,174,42,232,3,202,6,59,243,203,100,91,8,222,64,137,181,56,34,81,200,201,214,5,192,241,99,123,74,95,219,37,13,6,13,17,208,19'],
        expectedOutput: '0x9f485b50,0x7854e176,0x8ba4c7c7,0x8c357955'
      },
      {
        input: ['76,195,222,177,31,230,143,95,111,68,151,145,150,96,91,108,101,27,93,200,150,167,40,113,204,53,119,217,70,72,236,147,11,202,68,42,177,211,137,32,23,33,178,173,129,13,25,230,40,119,175,190,30,215,47,235,12,167,196,83,239,177,230,250'],
        expectedOutput: '0xdcd37542,0x741ec9ee,0x841d3fd9,0x582a3084'
      },
      {
        input: ['123,42,37,44,253,174,77,20,207,255,194,80,12,219,55,52,82,230,242,113,189,33,92,201,200,32,28,183,209,2,178,77,44,215,121,41,133,198,62,85,197,0,165,209,219,220,5,46,194,247,159,127,25,251,73,225,27,101,153,237,104,75,58,148'],
        expectedOutput: '0x65324ca5,0xf6888447,0x34e8ae7a,0x2073a06b'
      },
      {
        input: ['34,179,190,167,122,252,252,63,252,162,17,215,126,22,5,65,14,164,192,39,159,9,8,187,111,161,168,215,236,226,107,14,149,41,182,15,37,178,79,33,84,96,249,211,118,254,20,132,163,212,171,66,222,180,253,77,85,165,36,66,135,143,80,29'],
        expectedOutput: '0xaa1d54d3,0x79253d65,0xb5782761,0x77eeed6c'
      },
      {
        input: ['185,6,44,222,185,123,0,13,219,249,224,82,247,244,214,154,201,130,221,167,54,218,244,139,128,24,205,7,167,30,36,96,36,81,63,221,204,63,235,168,56,203,250,47,192,208,202,137,82,167,48,136,129,36,20,1,60,225,9,227,255,45,68,36'],
        expectedOutput: '0x3812322c,0x8cf5282e,0x594b172e,0xdb3cb841'
      },
      {
        input: ['126,131,1,75,194,236,243,250,184,237,41,120,189,243,1,16,154,49,152,28,85,172,29,145,142,38,116,141,84,184,177,210,59,179,29,253,159,16,247,87,253,33,207,187,20,208,203,175,1,99,203,86,16,232,231,158,15,92,43,99,20,221,53,80'],
        expectedOutput: '0xa9a98be6,0xb24cc1ab,0x4436fec8,0xdc510d6f'
      },
      {
        input: ['144,83,77,47,99,69,135,97,102,86,28,122,39,231,41,40,74,244,127,90,221,102,248,236,194,36,79,215,1,132,39,145,215,116,192,59,185,71,156,31,158,184,154,197,159,195,237,233,184,108,68,149,211,60,129,149,96,208,108,97,84,147,242,44'],
        expectedOutput: '0x6645ab52,0xa43ebf95,0x80da5141,0x38e261c5'
      },
      {
        input: ['8,179,103,193,250,3,225,152,187,123,93,90,62,75,67,246,183,135,139,138,196,12,32,36,220,140,134,49,32,120,93,40,43,196,233,38,199,202,190,130,69,28,220,132,103,31,122,30,167,6,169,107,18,201,143,239,85,21,32,117,142,125,157,185'],
        expectedOutput: '0x3770ed15,0xd78a1a4a,0x6dd8d45c,0x95aaf9aa'
      },
      {
        input: ['65,135,223,8,81,158,138,151,186,102,27,33,133,149,63,44,155,232,151,174,177,39,157,7,60,189,124,202,58,26,132,123,161,99,131,242,1,13,137,187,115,164,220,248,58,28,37,213,4,188,131,182,227,32,189,32,221,57,234,23,83,110,146,244'],
        expectedOutput: '0xdba74329,0x409ff73a,0xc85a2e9e,0x8cf3406d'
      },
      {
        input: ['210,21,231,211,34,112,143,149,21,107,142,79,135,179,36,140,111,168,66,83,200,255,115,166,56,93,189,140,204,80,128,158,101,103,113,136,216,0,29,237,108,171,60,243,94,96,127,206,8,193,33,209,192,148,119,249,241,52,133,189,132,5,91,234'],
        expectedOutput: '0x79d85b99,0x67592a6e,0x1d5881e6,0x88266c82'
      },
      {
        input: ['109,205,114,69,205,143,50,57,59,110,45,153,206,172,103,215,110,136,168,46,28,31,39,14,83,172,203,216,178,39,194,31,244,52,100,193,195,150,251,254,4,40,152,210,212,255,169,66,136,81,113,164,112,152,178,196,69,126,156,247,165,94,22,153'],
        expectedOutput: '0x16777ddd,0xd31f5fca,0x1d60b78a,0x97b8e0fd'
      },
      {
        input: ['146,122,90,85,16,85,84,20,125,236,230,82,235,144,148,115,225,5,24,82,158,202,22,227,72,178,218,237,16,240,134,162,106,225,247,122,54,75,142,180,55,116,6,35,4,154,150,230,160,174,56,62,121,78,33,193,0,251,175,16,235,53,178,85'],
        expectedOutput: '0x2cf88a2a,0x0d248dc9,0x0c5a1309,0x50d15f28'
      },
      {
        input: ['22,169,207,77,245,93,1,44,209,7,79,214,161,230,188,65,148,244,127,13,66,160,207,66,155,126,82,134,179,4,219,202,173,170,23,162,7,24,207,217,31,30,175,192,4,107,2,153,95,129,166,161,34,117,227,189,243,53,68,167,57,31,113,230'],
        expectedOutput: '0x80628f93,0x6b376470,0x8a3645ef,0x99fd4a59'
      },
      {
        input: ['202,136,137,209,160,88,170,191,118,89,127,123,196,129,20,35,3,186,196,37,48,167,226,35,220,38,202,21,70,59,252,16,195,133,225,99,221,140,34,83,229,162,206,170,35,226,205,38,157,146,75,205,57,46,240,22,84,187,43,154,246,39,170,186'],
        expectedOutput: '0x04e0bb07,0x39448f6a,0x8245ec08,0xf0e7146d'
      },
      {
        input: ['172,140,29,137,24,64,221,253,226,171,167,5,142,117,44,43,7,119,248,64,165,232,86,250,163,130,148,154,169,63,84,86,203,113,223,227,177,188,224,147,104,136,153,246,253,197,33,4,60,25,68,226,1,155,220,165,29,112,63,198,175,147,28,122'],
        expectedOutput: '0x9b0d4957,0xf697d437,0x0434e0b2,0xd8d94f73'
      },
      {
        input: ['4,252,93,182,184,62,73,32,198,226,22,195,167,55,199,228,80,11,198,82,166,162,247,195,18,54,138,194,201,166,60,205,162,154,131,91,216,205,123,158,175,146,97,87,201,40,59,26,51,1,108,218,163,99,157,181,153,39,119,98,206,180,47,112'],
        expectedOutput: '0x797258da,0x39ed93dc,0x02318871,0xa234c2a5'
      },
      {
        input: ['78,179,203,38,128,71,196,47,217,37,134,162,77,193,188,128,194,40,90,101,139,248,27,36,31,146,134,237,70,182,94,148,105,41,186,233,112,126,24,73,163,159,236,240,96,168,113,35,209,203,136,92,195,163,129,227,54,7,208,124,189,46,17,38'],
        expectedOutput: '0xe755a506,0x16fdbb45,0x62aabbb6,0xb336c94b'
      },
      {
        input: ['88,203,15,200,74,40,18,237,199,254,222,39,166,79,74,119,26,211,212,222,118,85,193,172,92,145,41,26,192,58,64,24,5,80,224,79,120,242,61,63,240,27,102,151,106,177,14,132,132,226,98,250,55,35,167,148,181,208,174,117,10,238,141,15'],
        expectedOutput: '0xdb97303a,0x9be51f42,0x75431690,0xc9d0e698'
      },
      {
        input: ['62,109,95,182,96,156,245,80,183,92,231,33,13,246,165,145,216,8,139,16,43,50,164,224,2,82,85,12,64,226,28,127,80,123,53,176,23,43,0,206,135,232,239,148,222,148,37,182,156,176,198,200,227,106,168,229,188,254,242,253,224,14,124,48'],
        expectedOutput: '0x0888614e,0xdc86994e,0x8f403b72,0x2dd1a02e'
      },
      {
        input: ['137,177,224,160,220,225,110,99,201,93,247,167,241,28,93,142,205,36,86,176,142,254,149,75,252,135,72,221,149,196,13,30,117,238,190,82,207,44,181,152,137,173,63,123,201,156,9,150,192,95,70,79,93,220,154,90,99,226,55,249,166,68,23,27'],
        expectedOutput: '0xb797e242,0x79e7d6c8,0x3001d0be,0x5bcf10a8'
      },
      {
        input: ['50,214,109,1,2,35,153,140,208,216,7,153,117,16,48,53,111,118,132,204,82,30,38,182,0,93,175,166,162,198,194,212,156,47,214,159,82,111,43,34,72,50,188,189,66,236,242,177,98,119,125,181,149,164,107,150,1,26,60,163,224,254,120,125'],
        expectedOutput: '0xd27e89f1,0x1fa05e24,0x1300ad6f,0x46407992'
      },
      {
        input: ['46,78,28,128,189,71,163,5,121,95,194,187,75,181,108,173,44,233,98,193,141,205,87,143,231,148,50,200,146,170,69,192,248,97,65,182,168,228,187,33,67,126,220,142,51,72,59,95,49,158,32,191,107,120,78,83,12,128,27,158,43,96,95,35'],
        expectedOutput: '0x2c07cefa,0x35e3138c,0x91f62e0a,0xac113b36'
      },
      {
        input: ['193,160,217,105,132,149,138,199,19,102,85,70,174,144,165,223,46,197,158,154,61,236,237,73,109,8,232,152,104,71,187,41,231,149,146,107,42,28,50,61,130,135,131,48,23,40,15,70,237,174,224,43,154,205,116,7,213,92,159,61,163,91,102,138'],
        expectedOutput: '0x48ce88fb,0x3642c510,0x830e46c2,0x6ee74ef1'
      },
      {
        input: ['240,248,245,26,20,39,87,150,174,218,198,198,2,213,12,239,131,236,26,30,185,143,37,142,235,197,203,143,32,49,25,16,41,15,42,61,54,129,211,229,91,153,171,93,110,183,76,242,163,103,16,92,246,53,234,225,250,181,112,26,230,138,42,15'],
        expectedOutput: '0xcb367d7e,0xa2a43d43,0x680b2404,0x5a27464b'
      },
      {
        input: ['153,84,76,207,213,31,180,48,184,95,141,38,22,218,24,185,65,40,21,55,94,255,24,88,180,137,115,154,19,157,169,172,242,245,123,199,20,48,248,204,143,133,243,166,95,11,95,160,52,117,215,146,116,240,234,41,121,93,195,140,251,109,56,237'],
        expectedOutput: '0x915d345d,0xfc093c80,0xedd353c2,0x469dc7cc'
      },
      {
        input: ['98,179,180,119,227,172,67,115,50,54,25,145,66,120,50,118,237,9,8,98,249,242,139,114,80,78,254,75,187,54,56,30,234,236,149,205,153,216,64,203,15,89,92,81,210,142,199,191,152,207,33,145,193,172,4,17,251,2,92,182,57,148,212,35'],
        expectedOutput: '0xbf76eb32,0xa584160d,0xccb09fd4,0xb82cc672'
      },
      {
        input: ['129,105,240,26,66,49,229,81,138,65,162,92,208,105,28,104,56,61,249,249,234,253,11,229,0,103,155,57,252,112,92,125,217,76,151,27,125,124,108,8,189,14,100,141,119,128,245,175,190,239,169,168,236,180,141,236,27,40,37,23,152,129,148,114'],
        expectedOutput: '0xa2c7ac54,0xcc50c3ac,0x08c44e29,0x842b428c'
      },
      {
        input: ['206,43,141,75,167,250,83,101,8,184,242,128,56,232,47,246,215,216,158,195,140,43,176,168,84,213,191,236,87,84,94,37,127,236,112,39,230,196,140,238,124,126,110,180,102,158,171,61,118,73,1,3,117,177,171,201,134,106,181,221,190,20,2,62'],
        expectedOutput: '0x389bcd94,0xeac8a3ca,0x1551d69a,0x9d7b44e2'
      },
      {
        input: ['0,115,101,230,55,241,212,179,111,67,103,214,225,18,19,87,92,20,90,209,197,5,154,76,112,79,41,46,99,44,108,99,159,209,73,214,194,30,137,50,97,240,8,66,3,27,153,95,48,244,48,245,249,202,65,105,25,107,152,125,151,4,224,54'],
        expectedOutput: '0xe0e34b0a,0xfc6878a0,0xe48e2536,0x00ff0743'
      },
      {
        input: ['214,42,12,152,72,149,202,169,133,210,235,136,238,132,231,30,120,23,19,114,225,85,219,251,192,115,120,87,120,88,141,78,130,153,230,202,46,177,115,179,131,94,60,113,227,35,143,91,59,163,205,28,248,169,23,184,28,143,15,148,232,156,226,106'],
        expectedOutput: '0xefd02ce7,0xdee70a8d,0x8c789888,0xf0174e8f'
      },
      {
        input: ['53,201,53,99,122,168,22,253,7,82,111,234,118,254,69,177,161,19,205,153,188,229,81,216,116,96,109,92,252,79,199,49,24,252,148,146,164,171,144,171,253,255,149,115,253,219,36,159,238,242,56,170,215,138,130,75,234,239,168,231,63,111,24,87'],
        expectedOutput: '0xe9e605eb,0x059c6297,0xc5104f91,0xfd17de74'
      },
      {
        input: ['107,173,234,15,88,122,187,85,121,80,201,118,43,237,21,25,223,78,195,182,216,70,2,194,53,170,169,116,25,194,204,132,111,182,147,199,48,78,28,169,159,229,31,202,211,53,228,178,131,167,105,91,237,107,29,35,21,199,151,46,137,99,178,248'],
        expectedOutput: '0x49f6eb9d,0xda421f49,0x059fd17d,0xf1f03207'
      },
      {
        input: ['25,69,191,73,148,219,242,51,193,18,253,148,71,225,70,202,137,175,37,118,26,66,153,47,9,49,93,146,148,15,138,174,85,73,247,233,37,234,28,230,252,25,122,67,251,192,13,132,112,50,250,138,116,148,186,126,197,23,16,89,39,155,7,124'],
        expectedOutput: '0x2c5d5b0b,0x61c8f5af,0xd76727ea,0xd6b2556d'
      },
      {
        input: ['228,255,101,9,233,129,239,229,154,105,40,149,42,53,25,154,103,20,36,219,168,222,89,109,246,106,198,29,5,206,153,233,205,254,243,182,127,226,155,25,76,195,175,118,248,200,16,95,220,52,58,132,19,148,241,9,254,184,38,3,134,191,236,83'],
        expectedOutput: '0x7deebe9e,0x38a6505d,0x03cce689,0x232e7a57'
      },
      {
        input: ['189,223,9,60,194,164,85,14,103,4,132,95,205,148,190,169,200,248,46,219,140,31,228,138,215,10,141,93,201,122,176,134,89,185,194,27,93,24,41,196,28,173,35,233,65,225,147,10,218,193,229,102,224,202,241,184,212,126,21,158,248,198,36,82'],
        expectedOutput: '0xffe86f69,0x7a07d7d9,0xb20c3f37,0xbcf38536'
      },
      {
        input: ['127,231,109,221,255,151,161,27,68,197,5,134,166,152,144,128,89,117,231,57,63,216,241,20,86,7,178,79,205,214,161,76,189,14,41,188,165,203,216,234,144,221,112,54,117,0,183,206,117,158,7,181,118,249,201,204,0,123,27,205,81,188,25,15'],
        expectedOutput: '0x6e24ede3,0x5a66134f,0xb325d9d1,0x031b6764'
      },
      {
        input: ['203,67,203,112,14,163,90,158,128,202,212,245,202,139,195,64,41,203,245,159,196,190,108,196,57,135,145,138,68,170,153,15,237,101,127,251,8,218,153,137,164,110,126,111,249,66,175,35,13,164,194,209,98,46,149,155,182,38,37,250,208,191,9,190'],
        expectedOutput: '0xab9a4389,0x95d14872,0xd0550d64,0xf036cad3'
      },
      {
        input: ['36,136,185,44,98,83,181,7,193,52,118,186,118,37,221,131,201,160,84,43,206,233,198,132,15,235,126,223,170,135,157,206,16,87,251,114,170,176,121,107,228,239,37,90,20,3,221,221,163,49,8,113,26,206,246,41,186,116,9,100,252,166,51,12'],
        expectedOutput: '0xeefe61f7,0x645979b2,0x74827c5b,0xa6d580c0'
      },
      {
        input: ['253,46,126,167,222,248,18,195,231,56,29,252,59,251,217,222,44,226,79,71,176,69,112,106,186,121,207,182,32,2,194,29,48,64,197,14,56,215,209,32,15,239,28,74,234,245,40,22,215,120,93,136,189,206,242,119,71,193,45,103,195,239,133,243'],
        expectedOutput: '0xefd68122,0x5e4dfec2,0xb3b8f586,0xbcae09d6'
      },
      {
        input: ['48,74,2,104,33,211,136,49,194,164,123,172,154,164,195,113,28,32,249,217,238,236,81,54,173,126,157,113,110,34,100,158,108,102,6,142,58,143,191,252,51,58,169,205,222,108,63,250,140,56,212,123,36,37,177,210,163,78,67,17,113,167,175,221'],
        expectedOutput: '0x9984f70e,0x22df9e94,0xa66e71ac,0x74930ba4'
      },
      {
        input: ['14,182,107,72,69,42,68,120,101,237,70,67,89,133,62,230,189,18,97,226,55,18,180,218,96,247,236,209,158,155,175,172,81,26,244,150,69,57,15,170,38,85,237,128,218,43,102,151,61,199,121,116,217,45,79,57,36,59,11,195,214,186,111,40'],
        expectedOutput: '0x06c79a1e,0xdeb39b0c,0x7622ce32,0xaba1ff10'
      },
      {
        input: ['212,100,190,25,157,205,195,195,34,177,67,252,220,169,148,26,112,13,142,73,59,221,131,95,24,142,34,239,72,146,23,28,246,213,54,147,163,249,86,197,170,154,194,135,67,86,161,180,99,47,253,158,13,128,254,37,14,32,20,86,178,43,115,168'],
        expectedOutput: '0xcee5c99a,0xe6efe6cf,0x6e6f6e6f,0x598b9ab2'
      },
      {
        input: ['1,169,59,164,162,146,105,77,44,43,212,111,129,117,35,229,164,33,131,177,161,129,215,176,162,235,6,84,23,121,253,24,34,56,188,197,202,37,18,246,81,230,102,210,91,137,183,255,170,59,177,76,188,136,252,94,115,2,179,138,124,176,162,158'],
        expectedOutput: '0x0ffce95f,0x97b811bb,0x3e3051ae,0x8923c9ae'
      },
      {
        input: ['232,94,99,179,132,117,169,213,91,15,167,182,153,95,182,67,154,103,143,86,239,139,181,98,142,104,237,10,24,143,168,0,238,12,179,114,129,93,71,221,108,238,147,5,77,73,73,231,176,216,62,159,100,243,2,242,91,239,252,115,126,164,115,108'],
        expectedOutput: '0x5acf254c,0xe844dcf0,0x1125cce2,0x08eceb4d'
      },
      {
        input: ['176,39,222,50,132,37,15,240,20,162,246,97,236,63,73,156,23,135,60,123,122,62,109,213,45,105,72,171,14,187,24,190,226,246,240,102,28,255,87,48,162,77,145,142,140,218,42,163,97,102,31,219,164,140,176,209,246,248,125,4,180,149,194,150'],
        expectedOutput: '0x0dd6d727,0x0b6469e4,0x4a2678e8,0x92bb5d52'
      },
      {
        input: ['139,179,253,167,178,84,215,84,161,105,226,45,67,13,208,165,115,239,128,24,124,49,233,114,41,102,118,221,251,56,116,135,235,113,46,158,197,6,242,102,111,213,147,178,226,99,87,85,83,216,109,207,9,87,65,50,189,183,16,185,239,132,64,219'],
        expectedOutput: '0x3ba4d729,0xeb3f388a,0x9069b737,0x1b9a9359'
      },
      {
        input: ['245,110,121,186,116,107,32,227,64,179,150,34,22,237,120,105,197,229,56,206,60,121,1,250,48,17,179,32,149,243,251,138,97,116,68,214,223,100,185,32,23,79,66,45,61,186,151,2,160,207,209,220,73,210,214,121,227,137,153,120,124,148,2,222'],
        expectedOutput: '0xb8f13aa6,0xd2751341,0x2a79e067,0x3f997729'
      },
      {
        input: ['8,70,180,232,170,109,8,193,189,74,238,250,5,133,252,165,85,205,129,158,159,88,23,130,225,177,250,94,69,252,60,78,66,240,54,236,93,62,173,26,136,156,20,141,33,17,50,118,222,180,20,126,12,44,0,237,221,251,75,34,247,135,112,58'],
        expectedOutput: '0xfb25b1a0,0xea9adea5,0xb3e4964c,0x171c4685'
      },
      {
        input: ['119,166,38,213,228,212,239,109,112,4,250,145,21,45,8,243,225,28,113,237,72,114,218,37,109,38,72,100,173,184,158,37,95,197,250,67,153,233,176,9,237,171,154,2,216,162,246,185,191,103,166,7,217,128,45,70,166,117,171,84,45,73,121,140'],
        expectedOutput: '0x85a1f4f8,0xe56b10ed,0x8e1f41a4,0x0f53b0cf'
      },
      {
        input: ['14,115,208,167,92,128,176,74,43,75,76,3,237,66,188,172,170,98,180,131,227,225,202,137,86,117,221,131,190,86,16,205,201,224,116,38,96,37,112,140,112,188,143,93,255,76,10,169,174,190,44,145,159,246,27,245,107,248,120,42,79,136,247,24'],
        expectedOutput: '0xabec59cc,0xdd65d901,0x9ffab408,0xf0111be9'
      },
      {
        input: ['104,107,62,201,144,174,85,0,107,228,94,106,48,104,19,223,38,63,112,197,54,139,186,161,132,50,203,211,187,194,235,35,46,42,236,190,216,65,191,67,38,29,173,86,133,192,53,171,0,166,112,54,49,42,215,181,92,163,136,23,101,116,59,147'],
        expectedOutput: '0x3dc361ff,0xaa91dfeb,0xcede09d6,0xfcd5e7b5'
      },
      {
        input: ['158,39,82,118,105,17,186,143,46,103,229,179,40,27,94,40,193,206,94,242,248,53,168,84,216,48,108,62,164,167,209,66,206,35,185,55,52,115,198,98,218,172,21,2,199,115,42,136,65,136,122,57,190,34,142,150,83,250,212,247,161,166,58,111'],
        expectedOutput: '0xdc902fe6,0x5b40c7d0,0x96355ca2,0x8d316955'
      },
      {
        input: ['201,243,167,254,102,109,96,64,25,118,67,224,233,109,104,43,246,227,100,180,5,242,74,88,236,31,80,141,197,138,253,142,125,164,140,227,17,237,35,43,99,102,11,76,212,116,119,202,87,220,126,92,206,200,181,187,231,5,72,172,143,69,59,12'],
        expectedOutput: '0x0bfe8703,0xdf3fe5c5,0x8f54d0c3,0xe309c9cf'
      },
      {
        input: ['233,199,239,251,180,18,38,23,121,49,100,77,165,219,23,252,183,149,89,134,93,14,65,69,19,137,241,162,207,44,174,184,244,157,179,168,175,217,192,40,11,36,117,176,255,140,173,183,33,6,61,127,20,126,196,39,7,181,201,214,226,119,143,214'],
        expectedOutput: '0xbff80516,0x44d28369,0xb34ade0c,0xa2ef7923'
      },
      {
        input: ['20,66,126,195,28,62,236,39,98,97,215,98,238,132,25,15,138,86,142,158,212,82,197,219,8,142,178,234,5,65,192,25,131,62,221,159,125,201,198,223,42,158,65,24,34,90,40,173,176,182,75,132,9,17,96,17,159,18,251,165,83,187,190,214'],
        expectedOutput: '0x8225f407,0x262d0203,0x787fb421,0x31ac718d'
      },
      {
        input: ['249,155,118,118,100,60,86,143,218,151,167,253,242,207,170,162,134,245,39,143,6,135,160,166,153,155,75,236,86,9,194,79,165,56,198,9,117,28,152,79,179,64,76,165,15,246,72,149,236,111,36,242,246,196,152,143,95,227,123,181,237,61,5,146'],
        expectedOutput: '0x5758ed0b,0x1982513a,0xf99aa162,0xe086f4a0'
      },
      {
        input: ['118,203,155,235,231,52,58,154,116,135,64,131,125,136,25,105,247,61,92,237,2,244,124,97,216,247,23,197,52,28,87,170,231,242,149,206,38,208,104,154,87,168,30,212,48,55,62,39,116,154,20,118,142,144,216,102,135,239,43,188,11,130,102,242'],
        expectedOutput: '0x34814f1a,0xbab332ae,0x19583645,0x341aa6d7'
      },
      {
        input: ['117,252,192,155,204,40,54,35,209,84,247,1,139,53,41,255,207,61,118,94,206,78,196,85,61,240,17,72,114,120,58,231,116,250,131,64,34,185,99,243,13,90,245,152,144,30,151,95,91,13,189,41,91,130,127,152,114,144,224,228,8,26,204,124'],
        expectedOutput: '0x6a784078,0xfd165277,0x8cdcfbd2,0x98bd1084'
      },
      {
        input: ['20,79,188,55,8,31,42,21,122,31,173,10,61,68,105,153,82,39,194,173,169,65,70,27,210,38,255,218,65,203,87,85,26,19,140,34,51,183,55,173,214,228,183,20,41,32,173,123,71,111,40,240,177,110,11,131,149,11,93,214,214,180,43,241'],
        expectedOutput: '0x0054c0a6,0x13fd9032,0x35dedd64,0xfd230b4d'
      },
      {
        input: ['200,184,19,251,111,75,168,69,47,95,89,88,127,6,211,199,118,252,183,39,106,195,170,255,206,7,213,164,188,1,149,132,185,169,127,40,244,39,109,35,134,199,124,5,205,79,204,67,75,132,106,182,71,20,181,21,28,139,185,216,140,79,92,69'],
        expectedOutput: '0xc41f8976,0x17021073,0xede5fff3,0xf13b1f63'
      },
      {
        input: ['248,219,109,236,2,218,15,136,161,139,141,111,219,90,178,38,222,29,220,37,49,146,58,77,29,243,37,169,66,129,238,58,92,91,38,94,53,54,230,215,193,116,70,156,206,248,195,172,21,159,209,71,49,11,148,78,254,186,247,65,59,229,123,152'],
        expectedOutput: '0xe3e0e9cc,0xe0edc913,0xdd94d10e,0x542000cb'
      },
      {
        input: ['64,162,246,118,216,221,77,153,81,147,54,31,139,249,203,161,152,156,232,202,167,124,24,165,54,16,230,114,245,98,10,54,4,0,172,220,221,249,117,46,140,171,77,23,164,24,184,61,180,160,7,91,29,31,1,83,47,231,197,37,73,207,91,77'],
        expectedOutput: '0xf851bd2f,0xe7a83df1,0x22805f19,0x83bfd22f'
      },
      {
        input: ['208,7,41,173,0,159,220,140,74,41,163,239,66,92,44,246,252,51,82,25,82,83,109,130,58,50,167,132,2,2,209,210,9,251,127,9,154,91,149,228,133,56,211,199,148,255,189,145,50,15,170,133,98,23,7,157,74,174,33,76,176,242,30,185'],
        expectedOutput: '0x44796f3d,0x8817054b,0x7d8298cc,0xcefeeda3'
      },
      {
        input: ['237,157,194,135,249,87,108,126,143,63,69,36,63,2,181,113,18,95,246,116,119,253,17,193,171,50,13,91,37,43,20,18,200,214,154,193,45,6,63,189,69,132,225,132,135,150,246,153,245,236,13,108,234,31,45,149,81,58,241,118,101,5,137,46'],
        expectedOutput: '0x12c9aef3,0x2e9d3ee7,0x353cc380,0xef1da54c'
      },
      {
        input: ['220,35,239,9,41,47,198,110,179,167,243,58,61,233,211,51,213,225,159,191,0,205,85,81,7,70,200,109,75,81,155,39,116,138,49,157,185,247,11,109,159,254,167,220,231,123,15,189,92,175,124,92,124,209,173,131,23,117,240,99,198,139,138,58'],
        expectedOutput: '0x58e6006e,0x15c8d1ff,0xb7e6ca0d,0xcf7a3bc0'
      },
      {
        input: ['22,187,215,207,179,227,60,82,225,228,46,201,95,62,134,187,237,2,23,105,212,196,236,235,58,221,78,0,104,217,59,126,148,18,78,71,245,138,153,215,110,200,160,205,6,38,136,243,40,159,92,252,100,72,232,158,37,54,158,142,15,217,12,164'],
        expectedOutput: '0x1d4ea892,0xfaf18485,0x187adc94,0x2aefc996'
      },
      {
        input: ['236,90,235,225,229,133,184,83,77,88,33,83,126,169,70,167,73,162,163,173,234,139,75,16,194,233,158,209,195,170,117,175,5,97,144,234,230,73,61,51,161,94,134,32,8,204,199,81,110,106,254,88,246,73,104,184,50,6,137,245,177,255,164,182'],
        expectedOutput: '0x3e2404e0,0x8bf74b02,0x29386a7d,0x1e943b05'
      },
      {
        input: ['96,53,160,70,126,221,121,31,60,255,63,68,203,6,149,57,113,147,145,103,220,250,31,14,0,168,4,177,167,168,103,7,221,7,77,91,229,198,123,33,197,186,101,144,193,250,201,50,141,91,153,105,85,184,119,85,96,123,7,8,36,110,15,1'],
        expectedOutput: '0x1a6bb229,0x581f0ed6,0x67f60201,0xa64e286b'
      },
      {
        input: ['118,93,93,91,35,216,124,233,146,225,121,83,219,67,133,104,158,30,209,243,214,72,72,55,196,79,63,232,190,78,233,52,171,70,143,207,30,11,184,177,236,49,4,199,116,138,47,18,168,0,5,127,72,78,182,12,157,245,244,91,67,222,143,239'],
        expectedOutput: '0xa17cfd6f,0x198a4606,0x0bb62ee9,0xe3ace13e'
      },
      {
        input: ['36,30,190,67,41,118,244,21,167,248,220,28,130,11,46,43,11,52,170,84,130,96,96,31,85,85,123,152,51,10,135,87,41,69,154,82,187,142,104,99,135,68,127,9,80,173,52,91,225,222,175,99,62,16,131,147,101,254,44,152,8,179,239,49'],
        expectedOutput: '0xe45cae51,0xfb4f6691,0x5a85a642,0x5478cb09'
      },
      {
        input: ['249,138,132,180,24,236,23,159,48,150,169,128,68,221,220,37,188,139,137,250,155,12,142,0,10,186,152,18,109,136,68,102,18,200,27,42,180,50,202,228,201,115,101,13,80,65,50,12,204,187,7,104,199,149,104,209,79,1,228,188,137,40,35,155'],
        expectedOutput: '0xa3166cc9,0xd7e4f8e7,0x6d20b9d3,0xdf7bc96b'
      },
      {
        input: ['240,62,197,164,112,143,136,57,2,237,70,83,46,121,95,251,52,102,99,252,251,203,205,74,204,177,7,85,217,42,240,201,104,182,109,216,69,246,18,72,227,88,155,18,209,250,13,6,97,112,2,92,59,207,167,8,129,174,93,90,216,78,36,64'],
        expectedOutput: '0x87b6ec93,0x4f8a10c2,0xf8dac806,0x7de01124'
      },
      {
        input: ['4,145,24,73,135,42,145,107,131,44,125,84,39,138,90,136,250,92,228,53,44,139,61,173,57,155,7,17,233,43,81,237,189,106,54,68,148,200,175,23,244,44,108,27,182,198,163,176,35,136,230,79,19,35,252,77,190,3,94,167,47,176,148,236'],
        expectedOutput: '0x8e76d8fe,0x2bfaedfd,0x541102bd,0x9ff433eb'
      },
      {
        input: ['26,203,48,174,147,224,198,135,12,50,163,195,248,70,115,27,206,89,106,226,125,102,47,59,106,141,227,153,61,119,133,87,66,181,6,213,149,204,93,162,254,0,101,246,70,216,18,21,50,124,247,175,227,38,234,77,179,205,230,241,69,107,72,135'],
        expectedOutput: '0x3f2fa44f,0x50f5d9f7,0x77eea51d,0x11144ade'
      },
      {
        input: ['32,78,93,182,26,186,88,24,186,189,15,0,149,33,21,199,157,12,118,128,50,97,205,230,46,179,215,115,30,31,251,63,110,88,245,136,18,77,161,204,10,176,204,159,209,226,103,110,238,221,239,33,62,188,7,109,112,222,224,142,253,219,205,107'],
        expectedOutput: '0x038ebe7b,0xf639d5d5,0x13269001,0x87a48368'
      },
      {
        input: ['51,194,244,69,15,149,17,25,69,222,185,22,192,32,132,174,253,115,207,60,48,214,169,160,180,137,46,178,101,252,29,152,190,17,222,206,166,239,231,235,205,160,1,141,192,134,60,190,249,11,250,41,226,163,201,150,44,248,72,145,244,102,42,178'],
        expectedOutput: '0xb5b1d3ed,0x53a343e2,0xb35bfe55,0xe8a3fb46'
      },
      {
        input: ['119,8,128,30,247,104,9,197,8,11,82,201,145,142,135,138,154,129,180,124,36,125,18,80,117,91,226,105,193,12,28,56,20,156,86,11,4,96,208,13,107,35,214,252,177,93,134,75,222,58,199,2,184,218,82,45,53,52,151,246,64,179,46,84'],
        expectedOutput: '0x66bc3f1a,0x1eaeb040,0xc80179ac,0x0fcf6643'
      },
      {
        input: ['79,133,96,84,229,48,97,80,83,55,76,5,148,210,80,114,13,24,116,197,242,198,242,39,251,137,29,59,60,75,144,140,208,240,224,181,32,65,5,116,120,81,121,12,36,201,126,49,225,242,246,211,184,232,250,179,114,23,239,174,99,127,58,51'],
        expectedOutput: '0x0ac985e6,0x0e7bed7b,0xbf0dadf6,0xa68974cc'
      },
      {
        input: ['111,26,233,143,91,238,3,211,64,124,223,100,70,93,149,39,79,139,251,8,115,245,187,229,13,170,148,112,41,206,163,152,233,140,40,68,123,43,24,187,168,247,31,238,85,180,21,164,63,16,172,178,6,104,152,19,18,44,131,60,250,38,212,227'],
        expectedOutput: '0x382acb16,0xa7678a2e,0x08ea0b8c,0x1065a8f9'
      },
      {
        input: ['179,252,40,46,40,64,233,208,55,8,190,140,188,211,49,251,228,221,173,234,69,69,253,88,113,128,148,108,166,104,79,89,101,119,135,141,183,112,93,239,120,27,123,52,238,172,47,210,138,221,188,207,34,185,39,148,57,187,0,224,36,79,57,137'],
        expectedOutput: '0x71065b86,0xe12d5c9d,0x161d9463,0x67b85f54'
      },
      {
        input: ['199,193,22,126,49,115,109,170,142,233,222,124,149,14,79,31,235,11,239,13,197,22,161,254,210,161,222,246,241,24,127,184,217,149,54,10,8,164,180,150,141,147,18,34,161,97,66,140,109,49,153,50,71,59,48,25,220,15,15,205,39,142,133,0'],
        expectedOutput: '0xba90ece5,0xb44de189,0x0b8d0a22,0x99ffd6ce'
      },
      {
        input: ['35,188,10,43,96,191,193,237,82,212,15,243,53,81,127,162,130,24,212,202,83,5,227,48,20,243,253,59,129,131,59,165,63,69,208,159,4,146,140,86,102,155,73,155,237,200,62,111,225,18,57,52,23,29,100,43,16,98,102,145,229,161,54,36'],
        expectedOutput: '0x82ff49b2,0xab677852,0xdb18cc80,0x4069f44c'
      },
      {
        input: ['231,7,195,235,153,79,66,255,234,139,154,215,84,216,71,53,235,128,105,2,157,206,46,173,48,148,63,21,54,117,57,29,124,252,8,21,75,74,20,53,214,175,13,42,135,84,95,114,212,200,117,114,150,163,31,198,55,94,219,109,212,20,138,80'],
        expectedOutput: '0x3a1f497a,0xba4d60b4,0x64a5a64e,0x4768a256'
      },
      {
        input: ['16,147,102,91,221,122,145,179,41,158,221,177,242,60,35,198,5,152,56,155,59,88,98,115,182,61,224,138,82,107,219,98,254,65,190,219,187,79,143,229,237,108,150,223,169,185,165,174,82,222,73,141,54,171,0,236,233,225,119,59,76,82,157,74'],
        expectedOutput: '0x777181ff,0xb622e6f8,0x73e2788d,0x919affb0'
      },
      {
        input: ['147,91,37,78,170,180,51,151,33,201,118,202,131,28,120,213,250,193,98,48,109,99,28,86,68,147,145,144,229,46,218,120,138,255,199,52,180,250,204,213,196,66,159,71,94,23,28,88,216,126,136,69,225,165,155,37,56,44,181,30,91,143,150,229'],
        expectedOutput: '0x2ec935df,0x80650df9,0x29d14fd4,0x8ca566e4'
      },
      {
        input: ['143,93,25,67,88,229,24,28,40,183,99,134,206,127,223,166,253,103,236,223,12,135,4,69,180,186,99,15,73,249,244,216,87,13,27,175,243,51,203,27,234,46,161,184,173,128,95,170,232,75,137,244,210,142,57,134,72,156,149,145,150,137,106,237'],
        expectedOutput: '0x52395076,0x23f5a533,0xbda5c82c,0x325f5fd4'
      },
      {
        input: ['151,133,156,138,185,103,165,163,149,70,92,66,199,187,236,175,6,118,163,216,4,221,95,76,121,244,221,15,126,71,252,21,205,152,159,134,255,68,41,148,138,133,214,81,64,195,0,70,57,164,31,61,129,126,137,250,114,102,10,240,174,6,5,123'],
        expectedOutput: '0x6fc3d324,0x03be5419,0xb5655ebc,0x6b2bc098'
      },
      {
        input: ['159,164,1,158,232,42,51,115,176,9,196,240,204,197,55,5,105,86,66,234,212,203,228,70,50,238,55,224,245,60,91,148,225,92,50,201,134,101,60,54,111,1,39,59,198,94,65,47,180,131,25,136,79,253,206,129,236,5,97,225,66,188,117,35'],
        expectedOutput: '0xc357342b,0xb06a6959,0xd318fcc6,0x2389654f'
      },
      {
        input: ['24,167,236,158,13,41,213,124,42,252,183,240,90,248,31,14,124,56,150,203,53,100,76,33,106,173,2,172,105,119,207,129,31,187,31,44,228,244,168,14,240,95,254,74,88,29,88,212,85,238,159,139,83,235,172,189,152,175,105,1,38,56,130,69'],
        expectedOutput: '0xcd27f94c,0x6a49eef0,0xb3d69456,0x70fad957'
      },
      {
        input: ['243,161,113,216,150,25,230,134,121,229,209,209,2,41,165,88,24,68,227,107,47,143,40,199,62,145,200,101,201,74,170,188,235,28,148,129,53,123,8,174,96,217,127,98,2,36,186,26,104,157,133,151,45,173,94,107,62,38,208,7,112,123,196,92'],
        expectedOutput: '0xd06d329a,0x50f44184,0x47f66bd5,0xd10bd3cd'
      },
      {
        input: ['151,88,221,204,211,229,123,51,190,250,150,193,31,80,219,135,238,97,31,27,14,125,134,77,164,87,84,20,210,24,112,105,113,78,53,68,51,176,120,242,171,14,179,202,94,142,81,76,239,112,103,254,238,238,75,146,69,159,166,23,184,23,128,41'],
        expectedOutput: '0x28b0fa11,0xbc968b07,0x835e8422,0x8bb516f1'
      },
      {
        input: ['101,181,109,152,102,229,138,17,243,61,219,82,204,44,158,187,157,6,185,139,244,4,29,57,164,195,80,92,218,208,133,63,133,242,216,235,216,98,252,203,160,215,29,108,4,188,39,161,194,225,44,182,229,73,239,137,12,63,229,231,15,106,38,148'],
        expectedOutput: '0x535f24d0,0x24d9bc56,0xb78a62a6,0x03a45066'
      },
      {
        input: ['93,254,128,53,97,124,0,1,84,30,109,88,218,148,249,156,117,37,82,91,110,65,228,122,128,202,97,143,52,136,35,145,134,163,198,231,32,199,232,116,229,85,204,191,234,197,91,95,234,173,186,88,238,159,210,110,105,52,253,157,188,32,47,66'],
        expectedOutput: '0xc81e8f91,0x7b8e77ad,0x6325f4f4,0xd0d063bb'
      },
      {
        input: ['196,245,42,228,188,18,88,161,104,36,96,82,233,187,177,211,104,108,43,86,11,253,196,116,49,193,17,237,226,64,48,166,54,90,138,242,108,226,148,212,6,244,38,239,176,216,194,24,68,237,111,79,234,51,195,28,245,212,9,215,21,57,125,75'],
        expectedOutput: '0x1a23e748,0x68bfbd8c,0xb7ad468a,0x7d038123'
      },
      {
        input: ['147,7,61,0,233,209,212,239,198,251,222,118,211,160,142,23,141,253,102,119,49,41,147,38,253,157,253,18,214,122,93,106,129,155,106,106,108,62,89,50,57,55,168,12,215,55,35,100,52,137,219,101,178,111,139,176,12,136,194,226,2,32,76,131'],
        expectedOutput: '0xbdf6bb8f,0x7e4c63f6,0x24a704a9,0x06e419e6'
      },
      {
        input: ['187,182,237,39,245,70,90,46,125,2,59,84,57,94,184,110,232,148,211,154,3,95,74,15,231,13,241,234,45,62,109,232,244,91,15,233,161,105,24,31,108,83,115,165,177,44,19,153,192,231,52,195,70,126,210,45,139,195,23,184,1,133,160,246'],
        expectedOutput: '0xca099e7a,0x815e15d4,0x3560ad69,0x4ec11e6f'
      },
      {
        input: ['224,176,223,129,25,247,160,133,74,20,43,252,64,62,149,0,37,201,195,107,72,149,153,211,88,176,140,90,53,44,80,21,220,47,151,246,39,55,123,113,75,166,109,139,229,3,139,10,204,78,118,20,227,15,232,60,191,116,150,245,160,230,10,125'],
        expectedOutput: '0x38c0b8fb,0xaebcfe11,0x15bd922a,0x833039fd'
      },
      {
        input: ['21,161,115,60,217,238,174,36,149,27,176,122,30,59,132,235,138,250,255,109,9,231,169,201,91,63,190,252,37,200,121,59,106,236,119,67,218,37,103,111,65,23,233,95,83,110,74,221,104,74,74,114,49,244,59,141,51,249,137,89,193,2,148,43'],
        expectedOutput: '0xc31e83d3,0xcc799b56,0x3c588880,0xe3716c10'
      },
      {
        input: ['238,11,110,200,49,214,56,114,237,33,209,64,143,28,29,248,102,104,106,151,92,165,36,143,158,173,232,95,175,124,139,157,136,249,102,185,207,158,43,189,191,252,253,79,24,27,71,126,131,177,22,223,86,58,110,244,232,87,83,151,211,222,53,91'],
        expectedOutput: '0x1ebe9841,0x97f3818a,0x92afb294,0x75b57a87'
      },
      {
        input: ['216,155,20,167,57,63,100,248,60,98,71,84,125,142,211,0,63,233,223,149,35,77,137,11,164,221,163,120,187,216,211,147,115,232,59,172,39,159,164,99,1,236,184,126,122,139,126,186,116,93,79,151,171,217,163,79,182,70,199,113,30,155,5,145'],
        expectedOutput: '0xcbc3709a,0x6e01bebc,0x03776cdc,0xe4b08f4e'
      },
      {
        input: ['131,64,61,170,223,225,14,225,205,198,95,72,81,222,2,197,59,81,92,230,42,255,54,224,69,253,82,99,152,87,244,27,151,49,198,118,19,212,87,224,154,183,40,235,149,42,176,208,124,12,183,166,12,237,135,81,234,217,181,131,48,169,158,199'],
        expectedOutput: '0xcf5059a6,0x3ba766fb,0xe63cac71,0x4df99156'
      },
      {
        input: ['219,100,61,238,56,149,206,210,76,247,189,225,33,109,177,157,122,104,68,134,85,203,215,64,164,140,195,212,54,97,155,17,198,216,255,254,109,205,209,185,196,142,154,230,252,76,131,118,180,199,252,10,146,211,74,54,96,13,10,150,110,165,167,52'],
        expectedOutput: '0xd5a4ca6b,0x35d41e7d,0x514e66ab,0xfcba6364'
      },
      {
        input: ['126,166,51,235,115,4,165,56,146,63,30,142,139,161,4,64,105,0,74,251,212,148,50,52,161,60,202,15,226,113,68,96,23,119,75,138,123,240,194,13,48,224,156,187,130,160,251,235,161,69,230,117,217,24,169,122,85,115,138,55,228,206,151,251'],
        expectedOutput: '0x29e8ed95,0x91072776,0x870e8d67,0x973b4973'
      },
      {
        input: ['69,226,133,192,211,72,205,3,40,105,190,170,10,186,149,171,255,124,32,217,148,201,83,233,60,221,32,32,171,183,27,240,154,160,176,109,232,126,112,17,231,46,187,241,232,81,156,232,205,188,193,97,133,20,75,193,242,107,225,157,35,252,142,189'],
        expectedOutput: '0xf0d2b2ee,0xa0e583d9,0xdf76cd4b,0x54a29ef7'
      },
      {
        input: ['157,62,42,133,188,154,150,164,200,82,149,177,163,50,153,112,238,90,209,116,110,28,53,96,136,23,254,171,19,140,104,176,202,146,54,135,44,204,43,244,30,192,165,193,242,62,49,225,152,3,85,7,31,138,103,167,161,101,82,181,241,186,101,188'],
        expectedOutput: '0xb3b2ebf2,0xe5a93ab6,0xcc8e6142,0xcb629a19'
      },
      {
        input: ['76,155,67,120,104,110,109,134,46,18,72,33,81,121,2,233,124,87,240,156,225,88,67,131,189,150,56,175,80,157,107,157,57,174,21,161,28,130,39,74,149,111,107,230,233,109,207,101,196,192,1,166,24,69,41,213,219,97,132,43,254,239,200,55'],
        expectedOutput: '0x556ec733,0x17d4fdb9,0x9cc7d539,0x02f275a5'
      },
      {
        input: ['157,222,216,185,96,0,4,245,111,111,219,88,221,171,190,161,107,191,71,131,4,112,88,223,209,221,11,208,204,211,7,106,177,224,35,18,224,39,7,79,151,227,168,116,142,102,21,249,37,93,124,42,205,212,9,159,177,20,111,126,232,118,232,153'],
        expectedOutput: '0x940964a9,0x677b8847,0xaa81d960,0x8bdfd0fc'
      },
      {
        input: ['86,11,171,54,51,179,134,202,150,46,62,36,148,83,29,185,176,153,227,126,109,237,29,31,1,140,157,233,2,133,131,89,144,46,143,195,225,21,141,119,67,203,155,215,31,184,145,207,81,116,77,191,97,106,222,99,246,123,76,249,0,207,82,144'],
        expectedOutput: '0x9d572783,0xec87b5c7,0xc9e4330d,0xc1eab012'
      },
      {
        input: ['254,225,84,223,247,225,87,58,173,242,18,204,171,163,155,252,23,233,187,121,83,153,220,74,20,40,67,20,248,149,165,246,118,249,213,109,218,44,168,135,31,186,83,202,93,239,198,116,216,130,237,43,27,201,117,48,242,184,68,234,77,233,224,196'],
        expectedOutput: '0x5e812889,0xbde5005e,0xf0a28d06,0xd54fb45a'
      },
      {
        input: ['226,181,49,189,226,217,68,1,147,152,203,240,135,145,101,95,19,82,138,47,28,0,95,14,184,163,248,6,141,216,202,111,141,251,44,111,213,113,112,104,9,59,89,144,205,190,239,224,16,121,15,44,121,110,58,50,18,50,56,159,10,2,14,152'],
        expectedOutput: '0xc27b1799,0xa7611dc2,0xf7adfd9e,0x883f5ccf'
      },
      {
        input: ['253,59,7,210,172,120,59,181,179,148,69,128,82,52,97,98,173,112,143,39,223,201,89,241,252,145,144,6,147,158,158,144,217,166,99,133,30,158,58,209,50,127,82,132,179,179,230,97,35,117,136,2,63,225,243,59,114,131,65,5,34,224,149,251'],
        expectedOutput: '0x67520de4,0x2031cb3e,0x3532706c,0x43cb7398'
      },
      {
        input: ['134,248,129,164,150,187,117,200,59,199,76,238,122,51,79,158,168,215,160,231,184,148,34,42,23,100,47,57,68,197,53,202,189,182,110,84,113,227,28,172,171,105,155,37,156,234,195,68,194,100,44,122,248,78,165,15,178,212,73,246,153,126,192,87'],
        expectedOutput: '0x0b24198f,0xdeb37fec,0xf4d72197,0x6980bb0c'
      },
      {
        input: ['52,46,171,165,18,199,82,189,48,237,226,204,215,166,17,153,10,61,20,2,139,185,17,62,141,90,52,39,216,245,126,12,35,41,178,53,240,4,242,33,241,213,237,200,123,254,98,133,59,118,135,199,47,152,5,188,243,57,227,203,46,97,216,82'],
        expectedOutput: '0x53593ce8,0xc8a5d9eb,0x151d91f1,0x6b94143b'
      },
      {
        input: ['138,138,135,123,142,122,156,127,79,137,71,202,136,169,79,195,31,214,138,78,110,143,11,97,201,238,45,247,80,5,73,218,143,209,85,29,75,241,156,154,123,227,100,3,141,179,198,172,137,81,251,247,224,6,89,169,244,134,161,68,139,234,31,26'],
        expectedOutput: '0xc13ff62b,0x58c4d878,0xa7202165,0x9634b020'
      },
      {
        input: ['187,116,55,6,102,211,160,225,182,4,228,67,183,170,240,64,251,235,56,220,241,145,133,229,23,38,42,162,17,73,188,204,189,243,211,35,198,115,4,124,120,232,192,47,147,176,112,142,155,168,106,140,57,240,113,80,22,155,242,39,228,174,244,162'],
        expectedOutput: '0xfec42a1b,0xbe54062c,0x705c44f8,0x5e979c49'
      },
      {
        input: ['161,199,197,103,58,202,227,178,178,163,226,69,83,82,212,238,250,62,122,51,46,236,131,69,135,117,108,108,35,96,14,196,39,211,43,98,157,14,20,80,178,246,149,5,72,105,244,66,168,110,117,214,90,248,27,226,109,136,78,144,232,92,84,16'],
        expectedOutput: '0x49379e92,0x1d822d0b,0xf9fc5522,0x5c062c44'
      },
      {
        input: ['47,127,114,205,142,134,29,64,125,178,69,197,28,57,8,196,168,125,154,2,118,182,228,227,62,50,116,38,142,200,54,190,72,168,139,214,47,168,22,172,90,91,113,118,149,121,58,61,247,213,63,109,139,36,80,201,86,196,239,229,141,38,163,213'],
        expectedOutput: '0x56a3938d,0x14139c52,0xbc485e05,0x98ba9ffa'
      },
      {
        input: ['206,46,171,253,214,193,169,48,28,27,167,177,148,225,238,139,182,46,248,65,82,73,10,168,13,250,141,154,32,48,111,238,94,26,236,52,219,149,101,248,176,12,169,69,237,152,208,164,198,201,229,24,18,240,192,31,234,78,186,10,126,41,248,221'],
        expectedOutput: '0x4f59e50f,0x9eb6a540,0x984c3c50,0x50c946cb'
      },
      {
        input: ['68,228,17,31,122,118,23,42,130,193,111,112,89,64,20,31,9,249,55,27,233,247,58,211,69,244,221,196,30,214,161,98,186,178,129,52,41,153,95,171,90,206,27,179,14,47,210,23,41,9,50,18,0,109,230,70,97,195,10,127,153,171,225,84'],
        expectedOutput: '0xfc3c0c7c,0xd19a827f,0x2ccbeb8c,0x9acef4d1'
      },
      {
        input: ['93,99,136,134,252,231,50,86,182,77,9,196,125,219,220,166,228,14,184,228,123,158,42,221,98,52,92,251,223,62,79,61,161,216,195,157,191,245,243,117,67,252,58,192,215,22,102,187,36,30,159,160,189,202,125,31,254,217,26,222,23,106,27,184'],
        expectedOutput: '0x49cd4440,0x4bdc1fed,0x08e4525d,0xd5819985'
      },
      {
        input: ['66,222,85,1,212,72,119,23,68,177,215,27,199,61,214,235,91,118,139,24,64,8,55,62,226,82,28,249,188,55,178,254,22,7,255,234,80,118,1,148,39,216,176,238,21,134,218,112,252,101,137,60,110,192,123,80,18,151,73,206,207,251,204,229'],
        expectedOutput: '0x7fe63384,0x180dd4fc,0xf0773a2e,0xe1014bb7'
      },
      {
        input: ['3,204,207,83,66,208,231,106,168,151,88,189,30,50,45,26,152,182,87,6,119,210,86,137,105,159,88,56,155,36,29,158,240,236,241,51,188,216,157,100,112,245,33,142,40,79,168,192,5,255,198,124,209,28,6,59,187,94,115,86,130,145,244,115'],
        expectedOutput: '0xd0519cdb,0xba16758c,0xdb8e0470,0xea5127da'
      },
      {
        input: ['125,229,166,58,190,67,158,46,56,192,188,96,15,100,32,20,100,230,145,53,2,151,112,190,245,228,20,119,117,9,234,242,238,144,44,172,211,203,218,12,139,150,108,154,251,141,174,95,115,63,148,118,214,5,52,203,233,72,67,94,81,45,80,64'],
        expectedOutput: '0xea53f4ef,0x203a07a1,0xeb2b983b,0x2233acdc'
      },
      {
        input: ['190,125,236,145,72,199,157,211,93,10,109,88,151,27,183,10,91,76,128,49,81,180,253,58,253,64,152,78,109,232,142,43,101,123,189,173,66,90,128,159,100,237,248,251,9,175,6,100,251,134,149,76,59,146,134,56,210,30,134,64,7,21,107,108'],
        expectedOutput: '0x2a316ad4,0x2f6071dc,0x83ba376e,0x347b2140'
      },
      {
        input: ['144,40,26,210,131,154,113,231,136,105,227,145,25,233,245,20,111,138,97,170,29,231,226,239,6,105,47,13,126,155,121,14,195,147,224,70,46,81,46,182,187,17,71,212,250,60,232,105,198,73,20,227,49,246,211,55,95,2,68,221,157,189,235,97'],
        expectedOutput: '0x47a2231e,0x5b205997,0x44c5b2aa,0x30c90b81'
      },
      {
        input: ['81,203,167,127,29,213,53,216,230,124,172,224,184,148,74,126,222,94,98,15,84,53,70,180,55,138,145,213,71,125,54,152,72,221,23,101,179,76,61,153,200,233,122,128,126,196,255,92,34,97,107,118,150,177,42,205,59,188,162,130,57,216,27,129'],
        expectedOutput: '0x3b2faa4d,0x14edf070,0xf095ee05,0x0f605958'
      },
      {
        input: ['182,50,231,105,127,36,2,71,14,124,200,140,64,199,232,98,40,83,217,190,4,3,139,63,191,46,193,248,6,220,122,188,15,97,37,142,133,40,213,147,164,157,31,229,100,7,71,140,90,32,74,94,36,214,157,227,4,95,220,10,59,86,199,74'],
        expectedOutput: '0xadadf882,0x99209a76,0xf9761dac,0xa718d3ae'
      },
      {
        input: ['183,236,216,60,20,174,208,185,75,239,158,176,247,229,60,81,6,135,176,42,93,77,13,97,172,233,107,232,63,50,50,246,31,11,51,51,185,3,236,4,242,138,180,233,112,241,59,118,120,235,160,213,56,173,54,229,151,161,205,214,212,255,205,243'],
        expectedOutput: '0x219e0135,0x726d33d7,0x9bdbcadf,0xf648ff55'
      },
      {
        input: ['10,0,38,195,3,19,200,245,157,124,223,13,109,26,131,229,5,35,186,61,209,240,34,104,146,239,62,102,239,11,89,249,11,127,189,14,146,133,4,48,1,227,61,111,253,193,84,2,228,15,63,181,255,98,29,145,81,92,247,64,103,80,58,115'],
        expectedOutput: '0x5581595c,0xab4e25c3,0x4125158f,0x64ccfe87'
      },
      {
        input: ['208,247,129,98,124,133,146,125,104,208,236,101,145,65,103,117,80,167,43,79,9,72,225,90,164,216,155,12,41,213,127,249,204,0,91,72,134,238,197,238,190,178,84,79,243,187,196,67,98,239,146,107,56,115,198,220,76,97,232,117,54,103,110,2'],
        expectedOutput: '0x1ff8d91b,0xe1d555a0,0xb703a9d9,0x4e18a286'
      },
      {
        input: ['104,201,74,238,183,15,220,117,193,48,196,180,236,137,247,78,120,138,186,176,253,128,141,73,225,117,190,23,221,44,25,69,246,99,51,173,114,15,35,52,64,231,232,44,112,224,122,233,106,52,153,103,180,38,177,149,156,111,172,121,156,197,190,146'],
        expectedOutput: '0xf4112d90,0x19d5fba3,0x8cb86998,0xed82fdfe'
      },
      {
        input: ['40,241,63,155,0,98,207,64,74,183,108,186,151,231,163,1,27,61,105,208,99,26,101,255,137,18,120,37,215,54,183,0,39,247,155,40,89,106,104,163,33,213,94,185,188,1,186,215,62,35,167,162,61,13,161,199,31,26,236,246,80,164,246,120'],
        expectedOutput: '0x4907eed8,0x9756ca6e,0x4d2f46ce,0x2c3d3f36'
      },
      {
        input: ['155,145,160,244,251,8,152,29,221,246,214,153,247,144,113,54,180,24,216,241,37,121,184,68,147,165,59,228,73,49,92,228,195,252,216,190,4,112,219,226,102,177,123,94,66,236,148,246,5,108,231,42,229,160,111,121,69,170,93,142,219,185,114,158'],
        expectedOutput: '0x85603f50,0x2a8d4316,0x45ccdc98,0x3be538ee'
      },
      {
        input: ['181,74,93,185,187,56,155,33,234,23,127,44,3,19,34,8,127,9,51,101,169,162,222,238,76,59,124,39,244,238,198,169,57,35,98,244,91,254,21,69,21,149,113,24,168,147,33,40,157,84,141,70,246,107,53,66,166,177,105,154,160,47,67,217'],
        expectedOutput: '0xa2066d8f,0x61235dff,0xeb1ec2ea,0x8abe6010'
      },
      {
        input: ['82,165,205,174,163,226,243,184,119,101,209,32,248,242,72,149,70,213,220,60,64,17,126,230,194,231,128,98,23,195,59,105,104,8,23,12,235,11,196,98,112,149,130,104,135,202,254,205,159,218,9,223,235,135,197,173,111,69,16,134,8,75,239,113'],
        expectedOutput: '0x34776bed,0x2ca22770,0x7fdad3e9,0xdb116fc0'
      },
      {
        input: ['84,7,125,63,18,65,161,130,215,36,234,94,238,232,44,142,194,53,109,173,189,51,91,44,120,107,178,129,182,161,242,10,168,111,73,186,176,235,60,135,15,39,230,253,15,18,139,210,71,249,127,4,44,218,48,164,69,226,37,252,132,23,6,44'],
        expectedOutput: '0x9c011a8a,0x25d4ac51,0xe353481b,0x23f8e354'
      },
      {
        input: ['134,80,231,55,59,35,190,74,74,164,71,90,182,211,44,254,204,171,2,248,134,51,156,203,21,194,199,153,217,206,198,96,30,173,151,89,208,85,163,27,250,234,117,176,189,161,174,137,76,177,129,210,228,30,158,249,224,101,147,185,51,89,25,81'],
        expectedOutput: '0x1ffb0680,0x8dcd5407,0x79fe8b95,0x4acb85ad'
      },
      {
        input: ['6,176,170,214,6,77,241,0,56,102,176,245,7,95,127,84,16,0,38,244,30,196,237,254,42,128,184,93,217,209,175,223,130,89,182,136,167,167,136,223,14,56,212,21,151,83,105,167,84,144,155,114,84,137,113,126,9,41,220,227,250,139,194,124'],
        expectedOutput: '0xfcdd23a7,0x1f53d38c,0x02c1d1cf,0xf20611d4'
      },
      {
        input: ['228,120,4,139,32,140,106,46,197,63,67,92,146,173,4,230,61,159,89,145,40,202,16,50,243,236,21,237,119,215,106,91,80,110,231,112,251,81,158,192,144,225,28,35,142,32,9,203,192,98,93,232,44,109,26,31,89,47,13,208,7,119,43,87'],
        expectedOutput: '0x7fa66946,0xccc28e23,0x3235c068,0xa74f9994'
      },
      {
        input: ['229,18,199,224,100,101,160,244,70,189,23,213,221,33,160,157,131,253,134,176,106,160,207,195,208,220,147,215,83,191,46,57,209,245,25,53,90,186,42,160,119,65,117,84,98,22,242,230,19,120,150,126,24,101,65,232,66,213,191,149,148,237,206,101'],
        expectedOutput: '0xd68997cc,0x32860a28,0x90f72160,0xdcc46bf0'
      },
      {
        input: ['226,232,155,60,162,197,221,25,6,82,109,105,104,95,79,124,215,229,250,240,74,59,216,140,16,152,34,164,133,240,10,104,216,165,164,122,106,129,147,112,212,1,217,60,96,40,184,56,13,178,40,88,238,0,228,254,152,6,163,30,247,173,134,207'],
        expectedOutput: '0x525134f5,0x4ebcd8ae,0xa33a3dd0,0xbf193fb1'
      },
      {
        input: ['82,42,74,188,172,221,44,128,222,6,188,63,46,117,119,60,39,159,148,21,159,120,20,56,127,183,86,118,100,220,69,182,6,143,114,178,109,158,50,75,164,239,138,211,100,1,15,139,160,163,161,64,27,181,120,154,108,206,16,208,170,86,134,176'],
        expectedOutput: '0x4136c04e,0x175f8251,0x2f2c3f7e,0x232229a9'
      },
      {
        input: ['229,248,99,82,150,149,158,59,132,40,14,232,42,29,116,202,192,21,10,219,202,130,118,54,80,134,6,250,220,140,171,194,132,14,20,26,163,178,85,40,219,99,16,5,128,132,207,64,153,218,28,99,92,146,153,173,24,159,167,245,43,82,183,175'],
        expectedOutput: '0x9fec8c65,0x23af735f,0xce2ee637,0x4457d6bd'
      },
      {
        input: ['96,203,202,4,126,31,44,89,131,60,94,3,193,45,68,90,7,96,190,100,242,87,17,10,247,184,255,34,11,182,210,107,130,156,111,0,187,155,89,62,216,183,66,153,228,134,243,236,230,177,80,216,9,97,226,0,25,226,34,36,152,244,144,26'],
        expectedOutput: '0x93389069,0xe412e1f2,0xca45879b,0xe3560dfd'
      },
      {
        input: ['144,255,26,76,155,115,138,115,42,204,12,15,82,255,251,56,177,75,16,186,172,243,186,197,213,220,234,109,209,122,136,97,121,162,173,20,22,56,135,64,4,147,79,87,147,74,143,68,149,160,254,65,147,184,7,104,148,241,213,101,107,93,199,228'],
        expectedOutput: '0x35147b23,0x27382e14,0x0b88f3f0,0xa6660ed8'
      },
      {
        input: ['0,116,249,22,172,128,86,177,20,166,8,167,240,151,235,134,55,233,199,202,161,206,50,53,191,8,155,42,101,98,15,101,214,8,123,131,136,210,52,156,120,60,67,104,211,46,238,11,23,182,213,184,132,8,238,68,16,137,110,117,235,125,219,193'],
        expectedOutput: '0x58f873cd,0x349717ce,0x673028f1,0x9bc07704'
      },
      {
        input: ['133,86,68,14,40,120,170,160,180,238,9,136,28,247,147,52,173,104,236,50,112,218,118,128,99,228,246,78,98,209,16,231,39,84,245,80,205,160,240,129,142,249,9,170,241,156,222,158,5,203,208,117,165,70,246,9,43,236,87,141,189,103,116,228'],
        expectedOutput: '0x2863a510,0x6722f536,0x3d31e465,0x0de7d272'
      },
      {
        input: ['188,106,52,137,10,37,10,152,30,20,66,15,176,33,174,181,236,126,43,145,197,33,154,240,13,242,125,202,89,241,174,21,91,227,158,101,8,169,253,38,189,64,54,109,97,228,35,77,98,78,222,39,111,121,23,124,107,148,70,196,134,244,218,225'],
        expectedOutput: '0xc50ce620,0xe1b46308,0xd5751522,0x49b77e15'
      },
      {
        input: ['215,120,71,223,33,68,6,222,132,60,76,229,32,111,50,130,189,17,170,44,138,193,168,245,86,238,185,220,226,147,189,186,12,4,153,45,73,159,12,205,219,88,179,251,199,229,126,132,246,40,176,128,233,88,117,63,70,47,27,40,194,217,226,206'],
        expectedOutput: '0x4bb00e6c,0xfd7c41ef,0x5f1ff928,0xcc3b4ded'
      },
      {
        input: ['221,124,252,38,27,8,244,247,96,167,242,39,140,112,171,131,152,91,3,130,179,121,193,249,168,221,33,106,182,4,57,147,128,53,186,155,61,174,146,157,85,133,196,225,245,111,100,142,202,104,16,125,225,209,118,137,174,151,243,100,155,44,248,27'],
        expectedOutput: '0xee4541a3,0x7055db89,0xefc0af88,0x6e915b73'
      },
      {
        input: ['97,178,183,158,96,73,59,181,206,255,150,196,110,251,82,56,99,98,181,68,51,43,205,226,195,192,70,94,237,62,122,78,240,49,237,80,122,40,5,73,40,156,13,150,151,95,207,250,193,132,62,244,176,11,214,115,203,29,209,184,91,75,7,76'],
        expectedOutput: '0xea17960e,0x76f29c11,0xd90ff906,0x8718c625'
      },
      {
        input: ['124,244,156,247,28,162,64,68,62,77,219,213,172,170,207,109,46,13,97,222,24,56,81,227,85,35,156,176,110,163,252,235,151,153,226,179,59,34,248,121,111,211,78,27,125,29,136,171,42,233,138,66,33,219,37,118,254,193,39,109,100,35,88,251'],
        expectedOutput: '0x7cbde344,0x6864244f,0x737d11ff,0x73596d78'
      },
      {
        input: ['188,58,175,247,92,167,112,203,122,190,230,247,219,110,162,5,87,44,71,121,8,109,239,6,46,22,115,147,58,203,142,246,5,61,238,97,228,94,44,94,29,18,85,248,128,248,254,216,36,69,81,44,178,64,51,225,87,166,116,145,114,2,135,119'],
        expectedOutput: '0x2a6f7725,0x08296397,0xbbffb236,0x5654f1d2'
      },
      {
        input: ['64,117,217,36,212,5,131,241,24,216,233,152,208,231,112,245,45,193,33,223,2,84,192,89,251,52,234,109,55,113,228,119,231,189,155,187,195,30,172,219,247,149,115,199,125,228,188,170,165,222,137,167,50,74,0,45,126,234,154,181,92,127,44,67'],
        expectedOutput: '0x739e6c05,0xec432c70,0x28718553,0x6e8583b2'
      },
      {
        input: ['60,200,254,255,230,170,218,221,63,78,165,188,50,97,102,215,63,240,127,114,58,127,159,184,106,58,110,198,185,154,9,245,98,7,245,73,177,207,38,240,29,203,173,79,45,19,39,108,3,166,222,61,37,126,246,143,184,100,85,113,254,94,102,97'],
        expectedOutput: '0x7c6d004a,0x82df7b74,0xba9bb968,0x4d26570e'
      },
      {
        input: ['101,91,170,22,43,208,7,72,156,180,152,201,199,191,53,203,101,20,8,138,146,254,26,74,98,111,187,97,206,33,194,51,125,108,74,168,60,81,240,216,5,136,161,204,71,215,151,172,235,160,55,125,158,81,199,1,192,130,98,142,163,36,194,32'],
        expectedOutput: '0xf3e9c53e,0xace5f358,0xc7d061e1,0xfae5a514'
      },
      {
        input: ['144,12,200,204,93,185,165,98,65,70,46,137,29,198,53,8,102,108,133,4,189,76,5,126,206,103,12,114,139,206,146,27,218,91,232,55,20,141,153,85,211,200,222,241,142,20,249,244,128,127,248,62,203,254,188,154,101,200,12,241,151,158,12,113'],
        expectedOutput: '0xc62624e9,0x1267a3dc,0xef03995e,0xe4262040'
      },
      {
        input: ['249,244,169,13,129,66,99,85,10,65,70,152,85,63,140,214,190,133,20,138,131,208,36,232,152,48,217,47,206,230,161,200,218,74,213,92,140,56,177,151,122,247,47,207,54,188,165,245,65,185,127,196,137,163,172,34,211,134,81,161,108,242,105,70'],
        expectedOutput: '0xaca68200,0x60e7d6b6,0x823cfc47,0x769e23b9'
      },
      {
        input: ['60,63,162,201,119,83,96,241,74,143,193,129,75,102,118,140,32,245,80,169,152,253,203,107,131,29,12,239,15,118,53,76,181,216,21,44,43,117,30,118,4,223,247,80,69,109,220,101,98,45,15,250,42,218,101,173,247,113,156,7,231,209,83,156'],
        expectedOutput: '0xde6b613b,0x90f562ad,0xf8dba834,0x0166a79e'
      },
      {
        input: ['169,104,201,213,221,231,75,225,198,66,49,11,175,14,113,17,59,128,11,101,90,112,18,82,225,174,89,201,127,172,101,41,20,46,254,241,21,73,210,219,139,4,231,58,18,88,75,77,216,86,178,50,198,196,132,167,114,221,112,241,137,214,26,157'],
        expectedOutput: '0x06e0ae2b,0x300cbfef,0x82957558,0xeffaad20'
      },
      {
        input: ['4,24,142,26,97,97,245,236,101,220,38,119,52,113,196,12,199,118,63,141,58,195,53,172,161,165,157,42,123,184,200,128,208,86,154,50,183,143,30,28,108,69,147,160,182,87,173,126,205,236,11,7,175,64,179,80,230,81,123,97,9,67,225,217'],
        expectedOutput: '0x06865a45,0xd2af67b1,0xb30dffb8,0xdf2725ba'
      },
      {
        input: ['153,123,11,81,11,42,109,119,111,1,23,37,88,196,163,38,176,175,45,96,239,225,176,213,50,43,55,59,110,24,20,8,148,32,89,159,74,198,22,185,199,45,222,32,242,130,70,162,49,115,2,32,84,179,246,134,222,45,193,77,69,214,85,217'],
        expectedOutput: '0x70467d4d,0x8cb56662,0x8bc0cf5f,0xc9842473'
      },
      {
        input: ['246,174,120,64,116,142,249,60,188,215,92,174,89,162,80,138,21,83,171,106,6,161,240,228,206,178,49,19,136,134,237,126,52,101,190,169,244,183,229,176,142,65,94,232,227,174,114,248,1,29,98,7,190,83,236,140,5,29,160,141,164,141,11,216'],
        expectedOutput: '0xe6433958,0x8997ddd2,0x349e2d34,0xc4a2041b'
      },
      {
        input: ['242,201,129,230,128,102,150,14,167,244,246,138,163,105,131,164,134,229,172,69,56,152,209,61,181,113,202,89,254,213,50,241,158,179,215,30,26,110,45,193,98,35,76,5,140,207,170,19,180,86,88,237,238,41,42,163,155,245,253,153,202,47,138,105'],
        expectedOutput: '0x30014ebf,0x603d713b,0xfc497847,0xd45e3d22'
      },
      {
        input: ['226,98,135,252,208,180,190,50,216,10,56,100,217,226,119,141,56,207,122,38,249,165,201,148,154,198,45,100,245,184,205,216,26,85,212,234,9,146,28,225,156,84,70,117,54,189,3,110,141,125,148,134,34,94,26,188,36,71,33,26,255,238,242,25'],
        expectedOutput: '0x9511586c,0x41e6b96a,0x1d9001b3,0x4b15f47d'
      },
      {
        input: ['67,198,3,77,89,32,46,245,116,116,107,171,50,110,25,191,235,174,69,14,12,95,202,48,166,235,74,166,218,60,191,29,3,195,106,92,227,153,81,87,13,188,2,63,42,28,254,22,202,67,36,214,162,238,6,73,218,81,239,180,141,174,209,144'],
        expectedOutput: '0xe248abcc,0xae1e0de0,0x619785da,0xfb282903'
      },
      {
        input: ['113,60,236,84,213,62,172,226,250,174,34,37,202,32,59,148,100,95,106,6,77,113,79,39,194,62,219,79,237,173,224,94,233,204,179,190,10,95,160,5,13,194,42,216,227,101,108,71,196,215,77,17,72,157,57,10,219,20,89,200,193,57,39,170'],
        expectedOutput: '0x462e37c1,0x72945669,0xf567bfe4,0x627cdb08'
      },
      {
        input: ['6,218,104,16,57,9,21,70,203,63,30,174,164,139,245,104,98,67,122,170,224,179,180,187,199,13,132,137,71,171,51,77,133,156,93,190,165,115,4,112,178,35,31,87,174,20,191,16,87,57,186,55,236,110,243,180,123,119,61,194,34,112,15,167'],
        expectedOutput: '0xd0d9854f,0x383aeddf,0x06258901,0xcff50be7'
      },
      {
        input: ['12,109,101,177,224,105,34,146,140,65,233,58,85,169,74,173,226,4,228,207,114,215,131,238,78,192,176,112,48,192,23,61,45,124,238,13,230,16,159,114,81,137,173,167,50,247,84,20,252,56,227,110,16,102,92,94,38,13,207,87,205,230,148,250'],
        expectedOutput: '0x8b9095fa,0x4d5a9882,0xbc9034f6,0x56630a97'
      },
      {
        input: ['99,130,7,73,147,166,187,228,47,104,139,97,96,223,118,92,24,89,202,40,192,39,134,230,52,85,61,1,60,209,251,159,84,2,232,231,168,163,203,216,12,87,57,108,54,175,200,78,9,146,118,201,185,253,175,237,82,237,238,142,190,233,45,18'],
        expectedOutput: '0x60f29b5b,0x48985625,0x4141c9bb,0x76ecd5dd'
      },
      {
        input: ['235,21,249,148,185,197,108,197,28,165,49,82,85,249,161,94,139,23,39,69,20,214,50,103,195,33,245,130,10,35,148,246,56,142,138,241,83,246,182,111,155,231,193,240,224,98,78,108,122,117,177,142,76,227,245,15,4,235,145,15,14,38,5,70'],
        expectedOutput: '0x653b6eb1,0x0d8c3131,0x8203e186,0xb1a789b3'
      },
      {
        input: ['180,143,56,7,133,238,118,32,214,55,17,182,154,95,34,20,213,211,162,33,183,152,48,187,131,194,202,145,232,207,215,156,94,15,163,227,254,25,4,212,80,21,138,234,116,173,254,73,128,161,106,55,57,155,243,188,93,189,77,69,141,36,225,235'],
        expectedOutput: '0x49ffb1ef,0xe44a71f8,0x4594095f,0x100fd8fb'
      },
      {
        input: ['52,132,207,50,157,211,6,237,232,144,216,92,61,214,166,190,119,16,245,176,171,232,108,8,166,185,77,51,222,46,30,18,178,237,68,79,192,74,61,168,218,21,5,24,235,171,214,99,187,203,19,103,180,128,111,90,57,189,141,23,235,171,41,158'],
        expectedOutput: '0x65d32e4f,0x4613e1d8,0xdc49ff5e,0x14508511'
      },
      {
        input: ['153,109,237,89,183,42,2,146,63,7,170,43,178,128,142,109,75,161,212,255,33,68,89,91,1,230,114,236,146,156,138,43,9,120,132,193,162,134,83,226,141,253,13,63,125,155,173,200,60,129,200,94,197,33,185,198,8,43,179,154,199,61,197,209'],
        expectedOutput: '0x672bfcb8,0x83c69695,0x0d78bd49,0x102798e8'
      },
      {
        input: ['181,73,146,88,208,229,58,93,226,71,157,95,226,74,39,30,203,239,124,145,17,53,87,25,97,10,179,40,72,120,249,253,193,139,85,145,112,143,239,82,214,140,177,184,214,217,215,161,200,83,50,217,137,138,242,234,148,165,18,220,29,12,218,223'],
        expectedOutput: '0x8268bf68,0xc04579cc,0x234e38c8,0x69461a58'
      },
      {
        input: ['151,47,112,8,191,95,90,149,235,12,78,193,229,37,99,173,120,149,135,1,31,121,235,180,31,254,144,60,10,106,27,161,154,140,169,89,235,4,238,215,16,60,152,245,97,251,162,218,145,41,219,176,163,199,100,194,197,245,254,207,95,26,112,249'],
        expectedOutput: '0xc41dc561,0xdd5e4213,0x16535b30,0x33aba978'
      },
      {
        input: ['166,26,82,145,30,65,104,46,125,1,35,223,252,197,185,141,239,148,62,146,91,162,84,32,151,82,239,247,108,96,240,18,122,67,164,152,132,12,198,1,13,233,224,10,174,153,151,157,46,213,47,137,120,131,170,15,214,153,6,66,249,247,85,115'],
        expectedOutput: '0xf374341b,0x27429f03,0x31eae601,0x017e52f2'
      },
      {
        input: ['58,249,11,190,5,209,191,19,186,160,29,105,57,180,6,103,138,54,241,2,185,155,17,143,52,24,210,46,15,39,161,73,32,173,7,37,126,198,56,57,102,85,162,160,10,168,7,148,222,248,150,152,147,167,39,200,191,249,246,206,32,151,23,64'],
        expectedOutput: '0xbab6d09a,0xbaec05d4,0xc815b773,0x647f1b77'
      },
      {
        input: ['68,30,102,195,229,158,252,75,244,158,235,254,70,243,146,37,235,40,189,127,207,228,71,143,222,61,93,254,212,117,63,25,147,165,220,120,67,216,196,55,118,175,53,188,162,199,225,142,239,158,13,191,131,84,78,97,145,171,95,101,32,158,126,180'],
        expectedOutput: '0xfa2ab0ae,0x75383999,0x2c4e52d7,0x7f91095e'
      },
      {
        input: ['67,90,44,135,50,240,190,168,160,244,101,66,187,70,208,171,229,221,106,104,49,184,201,194,99,40,40,132,199,166,56,10,1,100,145,51,85,80,220,245,68,65,55,255,135,8,170,108,229,20,212,23,204,157,217,48,198,1,180,141,168,236,151,169'],
        expectedOutput: '0xa9849b3b,0xc3dda2a8,0x01244d8a,0xa9d75fce'
      },
      {
        input: ['80,41,220,165,121,184,154,189,249,210,188,129,218,103,237,191,123,194,214,72,95,176,120,37,177,44,178,89,24,74,2,104,115,223,14,236,151,168,169,145,122,101,18,84,204,255,20,72,193,234,144,33,154,8,70,76,52,249,165,76,67,168,180,182'],
        expectedOutput: '0x3baa8dc6,0x7b0ace3a,0xcca2df7a,0x8fa6ed10'
      },
      {
        input: ['135,194,162,30,107,75,175,229,176,193,58,125,193,78,197,130,56,85,163,211,93,234,31,145,227,196,221,38,108,145,220,243,84,126,18,191,201,193,164,121,131,222,246,68,44,187,198,101,16,106,56,109,84,87,254,55,27,219,93,136,109,57,123,193'],
        expectedOutput: '0x02154711,0xcbedea00,0xf8abf557,0x6b99e8ef'
      },
      {
        input: ['183,141,128,128,79,36,249,210,3,240,22,47,171,220,148,188,70,204,41,154,35,40,209,63,3,46,199,112,103,66,49,30,208,177,158,31,214,152,241,217,136,7,8,51,227,157,239,42,105,25,196,141,65,150,204,68,196,147,181,44,213,230,74,165'],
        expectedOutput: '0xbe0b6841,0x20f196d3,0x1f145a05,0x48997719'
      },
      {
        input: ['152,233,196,110,129,181,71,9,188,79,60,160,236,44,202,86,69,142,227,134,36,175,202,233,66,127,21,23,102,95,189,254,72,129,108,201,55,179,210,243,2,15,147,239,59,93,69,128,236,40,6,16,215,208,249,25,80,14,48,182,110,237,180,182'],
        expectedOutput: '0x78604fe0,0x7d8d2d08,0x0d105f37,0xf58b5c39'
      },
      {
        input: ['111,32,128,166,211,82,153,213,97,45,196,156,138,9,28,118,49,34,135,8,243,128,33,67,143,82,249,253,63,173,179,174,205,51,84,160,134,238,117,231,27,58,132,165,67,160,28,117,195,163,125,182,35,159,249,178,241,242,175,48,159,99,223,108'],
        expectedOutput: '0x5ded110a,0x8c754b30,0x0548e447,0xfab3f6ba'
      },
      {
        input: ['150,51,12,28,33,129,4,60,187,136,226,255,40,254,116,235,161,241,161,196,144,154,119,129,140,38,178,43,137,145,151,32,196,163,60,230,37,64,34,224,200,4,223,241,2,83,220,163,69,126,104,213,24,223,87,165,5,9,208,143,154,104,175,94'],
        expectedOutput: '0x3a92fa9b,0x9860f074,0x02b9e100,0x8f47da0b'
      },
      {
        input: ['11,235,68,48,44,103,17,244,107,240,229,110,68,194,17,137,64,121,94,88,88,181,253,94,190,206,237,88,54,156,183,65,135,251,114,179,98,131,168,206,115,141,60,183,79,77,64,143,199,159,232,31,84,229,125,19,179,106,107,233,6,34,43,142'],
        expectedOutput: '0x98ac5b55,0x9c165db0,0xc18076b9,0xa6c0c33a'
      },
      {
        input: ['30,157,65,128,32,233,78,147,119,138,75,198,216,139,86,159,42,62,190,127,35,60,146,215,166,253,192,173,32,235,59,62,136,124,190,168,102,13,60,221,151,135,163,111,18,249,14,61,55,205,188,91,9,78,50,175,75,242,92,107,222,151,169,102'],
        expectedOutput: '0x547c3e7c,0xaeaef709,0x36b049d6,0xcb91915c'
      },
      {
        input: ['20,104,15,122,117,75,87,12,210,250,124,228,244,138,33,43,87,221,134,96,43,184,16,119,171,108,226,137,4,140,239,24,244,254,146,105,73,233,117,27,227,241,0,215,124,33,3,211,255,137,52,42,66,68,161,237,176,132,118,180,16,101,204,4'],
        expectedOutput: '0x24640e2a,0xd6df90b2,0x6cd66dae,0xfa2860ae'
      },
      {
        input: ['100,94,109,173,71,226,201,43,212,201,2,80,234,5,35,233,143,87,20,209,155,181,190,76,57,52,0,73,153,205,77,253,43,186,171,115,157,116,158,113,61,160,193,39,166,228,17,53,60,37,6,215,218,196,35,20,248,36,93,145,241,171,143,28'],
        expectedOutput: '0x977bc6d0,0x40319097,0xb03b14ff,0x3e73dfde'
      },
      {
        input: ['101,58,143,2,174,45,115,235,206,52,18,116,25,35,169,85,72,175,44,35,115,80,55,107,116,148,252,101,63,139,129,165,197,17,167,115,62,27,94,12,79,113,128,104,148,41,189,221,216,234,0,75,58,55,182,174,203,179,19,11,62,148,176,4'],
        expectedOutput: '0x1a0c25c5,0xbd1616ea,0x3f7efe31,0xe80f4723'
      },
      {
        input: ['165,87,119,228,114,214,240,194,71,113,42,219,154,232,184,115,210,184,190,12,239,117,186,187,40,205,198,102,97,118,106,7,205,226,235,64,184,219,2,255,76,44,218,231,20,147,90,230,75,24,242,59,141,172,246,181,121,188,28,219,50,134,226,255'],
        expectedOutput: '0xafea590e,0x72d824e0,0x5548b322,0x3acd697a'
      },
      {
        input: ['104,205,63,32,168,65,31,245,110,250,220,130,141,54,105,216,78,91,19,220,8,9,145,129,197,173,92,247,52,62,247,156,11,54,189,180,120,220,169,230,214,133,104,99,187,209,60,9,45,79,229,53,89,119,182,30,36,19,22,88,81,13,245,93'],
        expectedOutput: '0xe680f71a,0x62c2acb6,0x494e4a0f,0x78c7bf5a'
      },
      {
        input: ['67,178,17,187,142,186,161,101,63,10,200,250,219,4,3,8,84,233,61,173,96,244,203,132,7,225,221,88,238,210,181,50,132,198,237,18,128,143,119,191,153,64,185,116,68,189,125,152,166,186,69,6,174,17,138,181,242,103,14,225,57,195,19,189'],
        expectedOutput: '0x814ce2ea,0xadafeb59,0x0e4a4681,0x3d862b61'
      },
      {
        input: ['138,0,208,10,143,71,202,40,135,131,157,204,64,26,100,230,212,170,236,131,187,119,56,173,222,70,142,24,10,161,213,148,162,165,158,49,237,104,90,116,236,247,64,44,17,165,19,229,79,255,104,10,118,161,183,85,231,70,109,241,231,66,133,137'],
        expectedOutput: '0x50e4b823,0x256e3645,0xd67595ac,0xe188b3f4'
      },
      {
        input: ['232,36,187,213,140,21,73,120,12,138,165,29,47,184,2,126,183,107,136,46,12,63,131,243,133,240,229,109,50,106,246,26,142,177,239,27,198,57,147,210,195,56,239,242,240,242,112,168,93,248,214,105,55,89,92,189,73,65,42,123,172,32,150,58'],
        expectedOutput: '0xa654ece7,0xd0fd5cdb,0xcb400311,0x3500380d'
      },
      {
        input: ['210,133,85,152,190,233,107,129,33,90,115,18,76,227,186,169,219,144,18,19,233,111,208,50,176,250,173,92,26,67,151,236,201,236,133,135,213,240,9,247,74,124,9,151,96,195,64,59,83,83,78,60,194,30,110,114,24,27,207,51,95,102,31,40'],
        expectedOutput: '0x196419c9,0x61ade518,0xbd77e89f,0xf82a5733'
      },
      {
        input: ['82,164,175,40,148,184,31,223,53,40,118,149,235,182,208,62,9,31,122,203,61,232,62,86,3,13,137,98,115,168,138,197,77,58,237,225,242,12,192,39,52,54,188,31,237,141,93,246,172,215,194,233,191,0,63,195,13,200,37,128,113,176,69,190'],
        expectedOutput: '0xda8cb7dc,0x6516ec9e,0x2d5caccd,0x76fa11a9'
      },
      {
        input: ['234,51,159,220,63,96,4,116,150,192,147,131,77,241,122,249,200,60,227,136,60,34,75,73,235,112,201,92,32,14,26,10,65,185,231,129,25,235,245,176,171,136,51,249,121,173,242,66,233,213,202,37,248,21,110,227,133,55,63,166,70,89,176,135'],
        expectedOutput: '0x2eb5f8fb,0x4138c367,0xc76edf83,0x3c4ac57a'
      },
      {
        input: ['18,151,8,44,130,253,220,46,134,15,39,255,189,25,65,166,239,11,204,231,32,58,202,166,114,9,76,184,98,252,63,116,148,72,160,22,69,124,68,203,140,107,203,73,133,12,239,116,24,187,91,56,246,37,222,104,46,42,32,144,39,95,4,187'],
        expectedOutput: '0xe4398553,0xf7922c5c,0x4e3fa117,0x16dd3807'
      },
      {
        input: ['167,165,209,237,33,22,184,173,129,131,246,6,144,230,122,168,161,213,224,151,250,191,255,40,233,31,184,16,127,189,203,38,98,157,19,131,179,204,49,52,79,39,59,223,13,181,135,175,139,104,70,133,39,70,174,16,101,102,33,228,35,236,11,133'],
        expectedOutput: '0xaab95f8d,0xbecf8e54,0xb3891889,0xfdfb2c2c'
      },
      {
        input: ['137,30,9,60,234,58,113,58,97,172,25,111,97,161,30,236,9,100,114,48,170,32,64,16,134,97,244,170,78,255,47,215,30,56,20,8,114,133,66,212,49,92,67,146,253,97,127,6,197,241,54,112,17,118,128,151,216,116,65,38,116,113,253,146'],
        expectedOutput: '0x9ae2bdb2,0x68293fea,0x9f339b3a,0x5edf7e38'
      },
      {
        input: ['169,17,154,28,150,221,240,199,57,51,90,54,148,217,60,89,202,114,201,219,232,73,114,192,190,180,230,50,37,228,196,206,245,94,234,140,59,218,83,116,13,173,170,161,134,230,251,80,88,196,43,65,14,158,1,204,82,232,254,119,204,194,69,193'],
        expectedOutput: '0x96ec7d5a,0x2a6a43b9,0x4b7d42ca,0x4d09a244'
      },
      {
        input: ['32,48,77,92,10,161,208,24,78,123,185,213,97,180,37,186,121,81,251,135,239,252,83,65,228,81,184,176,19,253,114,51,45,191,143,56,96,96,80,175,219,9,132,60,190,169,246,55,250,241,190,233,238,17,42,210,98,226,131,117,224,245,168,13'],
        expectedOutput: '0xa29ea20d,0x70a9ab75,0x11d71857,0x138f4eef'
      },
      {
        input: ['180,56,69,21,152,149,196,115,159,72,175,93,241,166,148,236,151,82,213,133,99,0,88,197,226,219,58,194,208,226,208,132,26,21,153,178,171,93,37,74,165,213,167,151,123,59,131,18,141,88,152,240,88,240,181,59,203,239,253,155,209,205,31,236'],
        expectedOutput: '0xf73527a0,0xbec6ea61,0x1f0af5b7,0xdd944d0d'
      },
      {
        input: ['227,185,158,142,22,196,216,188,153,127,83,20,186,214,38,71,46,190,55,135,174,236,194,121,219,191,20,172,141,52,152,112,237,55,254,3,251,214,191,148,85,18,168,15,232,206,86,23,141,141,158,59,121,96,181,84,31,201,0,172,253,153,28,234'],
        expectedOutput: '0x5c12f0fb,0xb2afa762,0xa6cb2432,0xdf440193'
      },
      {
        input: ['208,26,238,203,240,173,95,69,192,7,84,168,213,170,191,98,55,93,158,176,189,83,4,221,28,5,137,26,158,166,4,110,192,242,57,177,160,152,246,96,159,75,8,116,245,200,215,45,37,117,221,227,200,226,192,228,231,73,254,133,239,3,243,176'],
        expectedOutput: '0xa4d1ff23,0x60fb37e1,0xedf8e436,0x957dca12'
      },
      {
        input: ['245,44,97,149,196,87,245,99,162,254,215,152,198,174,197,235,35,162,206,235,132,142,208,107,216,206,240,199,209,227,119,199,15,216,92,211,48,82,54,210,80,14,106,22,188,47,1,224,210,208,203,86,94,155,194,54,106,178,254,59,150,117,2,165'],
        expectedOutput: '0x376dbdf5,0x496f2da5,0x15cbe263,0x5883fc35'
      },
      {
        input: ['78,95,121,126,177,175,80,1,189,187,23,122,234,24,90,188,232,37,19,71,193,213,125,43,135,123,102,29,241,105,195,63,200,60,189,121,235,13,122,169,200,145,35,179,169,125,111,146,162,130,217,99,87,86,142,223,210,245,252,195,94,191,2,38'],
        expectedOutput: '0x11bc3e89,0x1fcc15d1,0x5605beba,0xae9b7d9a'
      },
      {
        input: ['251,191,159,231,204,25,144,149,170,179,72,83,48,183,229,210,58,190,54,145,21,196,112,231,185,109,170,23,44,172,61,40,107,220,15,55,245,159,204,159,82,20,243,130,204,216,84,6,151,138,151,172,79,8,147,8,117,61,32,161,233,93,201,84'],
        expectedOutput: '0x3315329c,0xf2d9f392,0x0222be92,0x100b53ec'
      },
      {
        input: ['58,216,139,47,119,88,207,201,108,194,75,56,154,160,62,49,42,214,221,121,222,112,130,83,173,162,244,150,255,190,234,57,150,118,105,14,206,56,215,58,250,35,115,148,195,177,198,237,135,163,103,101,20,233,184,193,139,173,88,138,107,66,196,1'],
        expectedOutput: '0xbfaed2c6,0x0c483c38,0x3720891d,0xdecb15aa'
      },
      {
        input: ['184,45,15,134,101,231,193,95,10,52,243,205,229,185,186,109,93,33,210,113,10,139,50,149,56,138,32,163,205,228,164,133,17,180,12,118,155,205,213,165,1,200,114,230,130,44,83,223,78,38,80,88,177,130,238,233,13,14,140,218,242,48,95,3'],
        expectedOutput: '0xe5312587,0x41a1011d,0xd153231a,0x0c4e930d'
      },
      {
        input: ['228,107,121,127,56,78,36,57,22,150,32,152,195,115,119,17,153,199,105,74,74,87,51,87,101,191,49,87,240,144,90,212,252,211,84,52,33,120,110,56,15,142,208,210,1,72,227,155,15,76,229,89,164,25,176,9,216,225,97,200,114,187,157,110'],
        expectedOutput: '0x0908b478,0xaa483005,0xcb3cb562,0x3b67367f'
      },
      {
        input: ['143,241,162,176,105,16,232,120,158,185,74,160,1,45,59,16,122,32,106,30,57,26,39,18,252,136,218,110,68,119,220,211,104,126,131,210,143,108,74,45,37,149,205,38,194,8,54,60,41,160,90,98,187,130,116,183,10,79,37,78,198,1,33,47'],
        expectedOutput: '0x250fc37f,0xb498b9b6,0x19d8478c,0xb070d836'
      },
      {
        input: ['127,165,1,14,17,75,60,54,224,9,92,163,18,146,223,59,51,58,157,238,188,18,165,198,97,202,21,39,203,54,86,74,219,87,89,236,163,149,34,131,158,126,38,176,17,6,235,68,64,137,50,252,155,215,194,252,161,215,35,108,14,122,182,233'],
        expectedOutput: '0x706a7e01,0x5e6ed28e,0x012406d3,0x40d5d982'
      },
      {
        input: ['209,15,214,116,164,248,248,67,119,30,243,136,36,223,204,100,104,254,96,3,213,35,255,118,250,34,226,8,156,152,242,110,168,200,226,76,192,218,143,55,249,131,191,29,98,139,130,202,137,226,205,94,5,204,212,0,238,182,8,139,79,250,249,247'],
        expectedOutput: '0x9e57ab3b,0x201d8b67,0xea811b86,0xf6e2b82a'
      },
      {
        input: ['194,219,67,131,182,211,186,175,86,122,204,184,5,78,130,143,49,79,237,54,27,194,54,9,120,63,148,199,57,141,190,252,105,2,127,31,213,57,206,43,179,154,227,185,233,101,72,26,180,53,80,207,247,135,216,112,198,109,55,255,250,246,251,99'],
        expectedOutput: '0x52215af8,0x45c35d59,0xdea6fdaf,0xa07f94a0'
      },
      {
        input: ['248,122,130,205,180,80,248,103,235,219,32,212,64,104,238,244,158,62,195,149,197,155,5,139,8,61,139,3,51,134,102,43,1,233,248,181,57,240,28,36,203,61,248,11,165,230,255,67,37,194,217,234,93,222,118,102,27,1,105,78,135,207,121,136'],
        expectedOutput: '0xf2b8f343,0x89cb024d,0xcaca8ac0,0xc89b8331'
      },
      {
        input: ['184,113,61,242,97,90,22,44,151,15,55,60,245,54,128,26,248,89,5,86,55,123,188,83,124,37,161,3,244,27,140,173,140,201,159,238,35,181,26,186,196,82,247,186,136,119,212,129,208,217,215,7,84,147,90,208,184,252,212,172,23,96,89,163'],
        expectedOutput: '0xddd7f903,0x4c2d3f8e,0x6b5d7e81,0xb2cb79a9'
      },
      {
        input: ['41,248,145,77,174,172,7,114,254,254,44,134,117,1,7,69,218,222,77,47,113,167,255,41,163,211,214,186,51,47,94,93,40,239,170,214,155,177,72,153,176,117,32,37,118,39,107,80,6,184,127,119,95,127,161,3,82,119,189,134,166,27,227,206'],
        expectedOutput: '0xedc3adde,0xaae118be,0x0608f44f,0x37d35659'
      },
      {
        input: ['11,141,164,166,62,237,64,238,98,96,20,216,135,127,40,141,55,168,5,150,39,166,153,121,29,87,255,195,114,226,146,125,111,54,36,174,35,100,156,133,196,176,93,75,47,134,217,102,46,222,253,85,132,150,206,161,237,206,100,96,176,246,221,32'],
        expectedOutput: '0xdcd97d8d,0x41163366,0xbc623892,0x27074fcb'
      },
      {
        input: ['45,1,206,80,101,106,214,41,27,51,117,74,185,78,177,231,44,174,60,176,68,11,81,50,217,181,146,137,172,111,169,217,113,119,41,214,226,255,0,253,51,117,71,236,195,248,212,239,166,16,159,235,27,240,29,244,165,175,126,81,30,39,42,143'],
        expectedOutput: '0xe25eefaa,0x89265c69,0xc7fdcc7c,0xc8d9038e'
      },
      {
        input: ['159,84,102,129,83,102,126,134,219,197,115,158,190,71,141,100,87,44,79,115,28,108,103,193,27,229,19,58,13,61,201,172,145,47,45,229,149,171,107,112,112,222,14,46,37,155,147,125,199,226,240,227,79,87,165,106,61,184,164,74,245,110,246,135'],
        expectedOutput: '0xa9787a14,0x695f8991,0xcaff742a,0x9e747d9e'
      },
      {
        input: ['157,35,108,51,206,215,163,62,182,178,109,219,77,0,88,21,226,72,248,49,160,157,156,221,85,64,39,75,174,29,210,76,64,62,127,14,21,34,76,203,212,185,167,34,185,255,55,156,72,47,205,232,205,105,197,34,170,236,109,88,9,63,164,73'],
        expectedOutput: '0xf8394071,0x00c5f020,0xca2bdb3a,0xc0595a6e'
      },
      {
        input: ['125,35,87,147,70,163,94,26,93,5,60,22,5,115,178,77,163,128,53,112,233,250,146,147,230,0,236,239,63,144,56,189,180,143,80,250,50,174,20,143,180,81,166,185,196,88,6,103,216,59,215,194,53,106,85,27,106,65,10,169,210,66,102,134'],
        expectedOutput: '0xbed36c13,0x0181a633,0xd45afd5a,0x0ccd9471'
      },
      {
        input: ['209,182,128,3,101,148,147,25,229,57,210,170,145,216,17,106,19,233,44,72,83,129,99,189,195,109,102,149,175,205,27,128,131,155,131,232,47,22,1,21,79,211,191,225,171,208,75,190,185,119,6,12,248,105,201,187,214,48,80,133,253,107,5,128'],
        expectedOutput: '0x3d14e1b9,0x64c24bab,0xb33d29a5,0x91b4db3a'
      },
      {
        input: ['6,137,105,54,159,106,75,239,62,10,208,233,218,27,168,148,146,174,160,138,24,106,70,238,154,150,116,151,2,121,23,8,2,128,62,162,235,137,145,41,147,97,18,110,124,186,2,14,105,162,152,129,12,222,111,166,117,227,61,119,93,85,127,95'],
        expectedOutput: '0x25db1e73,0x87ebbbf6,0x809d7ac7,0xee325fd1'
      },
      {
        input: ['213,190,1,192,71,146,233,219,243,252,73,111,182,75,125,31,237,22,160,250,244,16,160,105,243,222,224,80,51,96,176,8,30,177,201,101,68,178,64,55,174,137,167,101,212,36,132,194,58,37,188,47,53,92,152,40,58,121,121,109,217,41,118,247'],
        expectedOutput: '0x8eca577a,0x53f4e27e,0x38b278f4,0x22d57d27'
      },
      {
        input: ['218,63,92,30,241,157,86,160,38,253,5,251,33,137,189,92,174,121,139,227,213,35,12,16,156,133,125,117,174,243,108,136,50,201,167,36,102,253,196,140,250,201,135,27,82,68,119,1,189,2,228,147,38,240,163,194,117,32,56,35,20,164,172,70'],
        expectedOutput: '0xd0ab6e8e,0x28e2beae,0x8334f257,0xb5a65b83'
      },
      {
        input: ['109,83,106,211,80,46,96,74,247,231,101,74,44,221,75,233,223,47,124,5,32,31,200,149,64,0,185,84,164,101,154,18,184,5,229,8,51,69,82,43,45,183,117,89,148,192,66,116,239,191,121,15,222,65,165,30,65,94,114,230,195,13,248,123'],
        expectedOutput: '0xbd31e1c7,0xc5819647,0x5c6ec242,0x624e8edd'
      },
      {
        input: ['18,221,131,69,35,213,112,80,140,229,169,33,165,235,149,149,170,14,164,137,80,73,167,145,167,26,119,106,39,111,229,57,77,104,126,112,61,239,192,202,212,105,235,122,84,128,15,255,142,179,136,222,253,47,112,164,73,231,15,112,87,244,169,164'],
        expectedOutput: '0xb436ed61,0x4e6eb55a,0x9cdf02d3,0x14314e04'
      },
      {
        input: ['93,40,20,154,23,212,100,235,61,79,101,145,207,116,144,94,40,24,60,37,72,172,201,145,148,216,2,235,205,171,143,42,211,163,196,234,119,41,214,180,120,59,69,72,176,214,166,216,238,226,253,54,143,198,200,35,159,202,14,108,117,157,150,73'],
        expectedOutput: '0xaef5d0d8,0x5da32de7,0xd2efc37b,0x5b57d5ae'
      },
      {
        input: ['64,90,51,183,131,9,107,252,69,176,68,245,134,234,205,117,204,202,171,91,144,115,126,47,61,140,155,179,41,49,252,105,140,47,32,15,57,139,11,126,60,79,115,194,57,64,55,6,10,227,97,154,86,224,202,148,108,101,71,150,151,67,255,35'],
        expectedOutput: '0xd35d1be7,0x4a73954f,0x37151690,0x26b3286e'
      },
      {
        input: ['114,32,50,171,171,62,41,231,141,156,170,199,220,225,205,230,196,46,129,27,14,75,175,123,176,246,17,71,57,16,106,171,48,157,87,220,219,128,195,104,29,109,47,249,79,252,224,19,43,97,46,57,172,221,180,92,211,197,164,12,214,14,184,6'],
        expectedOutput: '0xc92989c1,0x6c5dae04,0xea8f34bf,0x4c8331d6'
      },
      {
        input: ['171,15,226,134,143,166,239,172,19,30,166,98,27,134,118,70,231,164,127,147,130,52,239,85,249,147,98,207,162,26,214,77,41,184,212,184,94,195,101,114,225,11,212,252,145,74,66,120,239,194,11,113,246,250,198,239,142,40,191,48,66,149,125,107'],
        expectedOutput: '0x652a5db5,0xd091b6c9,0x48d4e412,0x04a961c2'
      },
      {
        input: ['77,81,36,172,20,137,30,246,148,242,242,37,61,53,157,44,247,168,157,237,162,99,220,48,140,155,96,206,48,222,58,126,47,94,42,68,231,72,58,123,58,44,160,119,97,61,163,88,229,64,69,135,164,34,184,48,189,24,254,238,246,56,108,38'],
        expectedOutput: '0x90bb8dba,0x4766ec46,0xd5ff7a06,0x111ced97'
      },
      {
        input: ['150,150,106,125,222,164,248,24,208,152,144,50,213,51,138,186,116,208,66,24,242,250,72,175,18,70,157,9,127,9,47,21,159,153,147,125,61,139,150,13,36,38,63,249,89,202,180,205,154,246,229,140,240,45,59,2,116,217,11,243,226,58,8,130'],
        expectedOutput: '0x5856bb6e,0x701afb23,0x98d69c57,0x61c52bf0'
      },
      {
        input: ['211,155,255,16,39,149,30,75,187,93,68,21,39,248,226,193,238,200,77,222,245,137,225,105,98,236,92,68,39,101,198,250,0,198,11,39,91,41,114,23,134,183,44,174,175,14,111,158,214,189,124,204,70,93,53,168,74,146,236,113,247,179,107,247'],
        expectedOutput: '0x8a95599b,0x2cb064cc,0x79c7dc3a,0xc840f049'
      },
      {
        input: ['121,118,31,212,159,145,235,38,72,23,212,248,38,67,150,252,0,18,200,70,112,254,238,186,144,219,43,135,142,150,126,7,13,157,219,172,47,199,210,119,222,166,111,4,234,5,1,234,24,201,49,136,199,31,66,87,250,109,222,136,3,93,143,16'],
        expectedOutput: '0x89e3d363,0xe5078f55,0x0e4dac53,0x4e72f405'
      },
      {
        input: ['250,107,189,41,50,143,161,16,54,16,21,32,22,22,10,46,223,59,182,167,91,248,254,85,101,221,222,104,58,109,121,52,216,54,94,10,197,255,27,251,15,48,27,37,70,38,83,37,97,9,204,188,1,203,18,102,168,240,207,226,93,72,22,54'],
        expectedOutput: '0xe7e8f4e5,0x7554b5a8,0x14d57060,0xa210ef07'
      },
      {
        input: ['126,116,64,67,115,91,63,131,139,90,168,209,128,252,247,226,5,195,158,7,142,176,109,54,160,60,24,254,132,47,52,2,163,116,70,23,208,133,154,91,223,66,45,96,62,36,66,68,231,224,75,118,145,184,172,49,245,197,47,121,244,99,124,151'],
        expectedOutput: '0x0c530f19,0x6d049616,0x93e1ee48,0x5bff0620'
      },
      {
        input: ['216,194,174,168,71,72,3,38,139,48,134,201,84,200,13,60,169,88,178,58,17,94,107,6,35,155,127,23,254,251,175,214,189,93,126,4,166,130,43,49,178,177,250,7,122,8,67,35,96,245,93,113,83,200,119,119,99,247,142,98,242,61,56,176'],
        expectedOutput: '0xfc6515a8,0x37dac456,0xb8612f24,0x70e71e8f'
      },
      {
        input: ['155,183,180,65,57,223,114,235,145,108,242,11,116,53,46,213,42,139,70,126,83,190,245,183,181,131,25,167,193,81,87,92,8,12,157,65,235,15,45,124,123,31,135,240,85,181,197,127,64,11,253,148,201,242,75,126,118,100,38,55,181,125,147,190'],
        expectedOutput: '0x900d25c0,0xab097b89,0x53b8deb7,0xe55c1b09'
      },
      {
        input: ['137,48,255,117,63,44,241,186,76,121,170,161,46,111,32,111,123,30,3,68,16,78,195,134,178,233,189,103,102,80,37,240,128,37,101,191,81,86,122,157,207,36,62,254,148,95,109,15,125,112,83,141,190,22,20,112,255,209,215,102,34,253,86,162'],
        expectedOutput: '0xd2c215e5,0xf3f9a546,0xabd3a0f8,0x2e744154'
      },
      {
        input: ['34,187,98,115,17,220,17,225,0,79,223,148,174,76,163,43,188,247,185,122,13,205,234,13,158,193,115,192,190,201,99,224,132,197,84,149,161,101,118,161,180,85,54,99,161,217,142,93,208,71,215,222,20,193,235,179,131,94,115,65,39,214,34,171'],
        expectedOutput: '0xdf69d024,0xf4ad6b00,0xdde39250,0x86219010'
      },
      {
        input: ['155,118,64,60,219,183,222,143,12,20,242,174,237,129,11,190,200,227,156,221,164,135,144,39,229,3,105,12,218,139,183,117,1,247,178,220,174,144,107,187,164,94,105,145,223,116,79,167,87,235,132,252,114,20,35,87,24,140,99,242,23,26,103,24'],
        expectedOutput: '0x58f0c75f,0x31433155,0x8700d3c7,0xa8d2312c'
      },
      {
        input: ['18,25,244,192,169,96,123,77,190,228,223,157,89,46,68,176,26,201,172,140,221,208,228,245,92,71,231,116,98,79,140,116,104,129,52,18,225,176,95,159,148,62,60,237,109,128,158,135,73,74,19,39,26,247,28,119,63,4,235,161,83,119,21,187'],
        expectedOutput: '0x08364f46,0x53649bf8,0xf0019cfa,0x43025618'
      },
      {
        input: ['248,73,205,217,249,45,120,142,107,180,123,216,53,25,95,126,100,115,165,126,106,194,245,169,198,224,74,25,88,95,212,80,169,162,42,162,207,162,48,58,87,172,19,140,197,114,10,41,229,176,168,80,114,157,249,56,126,68,81,214,163,37,38,76'],
        expectedOutput: '0xf149b8f4,0xdd154dc4,0xff6dfccc,0x57c4167b'
      },
      {
        input: ['199,80,239,150,243,31,209,74,203,228,214,145,86,224,186,60,144,98,140,2,0,133,58,126,201,139,84,109,177,122,185,120,203,168,15,190,200,224,8,147,196,222,36,26,190,223,86,79,65,226,81,65,104,140,191,49,23,19,158,200,142,88,65,89'],
        expectedOutput: '0xcd839de1,0x01609590,0xd314c1cf,0xe472cc4b'
      },
      {
        input: ['0,80,23,200,48,31,92,244,253,128,14,187,95,101,10,161,71,92,226,175,232,162,225,255,181,127,200,67,215,9,156,216,89,179,160,137,210,252,125,207,125,139,139,220,240,149,125,56,241,96,231,217,2,200,217,183,72,161,251,31,170,151,247,3'],
        expectedOutput: '0x7f59c49e,0x5a922d3c,0x07794685,0x6d807688'
      },
      {
        input: ['75,152,140,29,148,9,237,17,148,120,238,133,13,107,189,255,203,164,216,205,109,177,133,181,82,128,212,252,23,204,255,98,100,139,128,248,148,109,10,41,229,248,174,242,99,107,241,47,15,202,252,124,123,129,49,206,1,6,202,25,210,202,123,54'],
        expectedOutput: '0x5ee802e4,0xa75f8334,0x09620e80,0xb35534e5'
      },
      {
        input: ['85,251,46,234,104,56,19,77,48,193,64,148,44,49,195,59,251,191,184,119,65,233,69,66,239,15,91,193,217,215,247,47,210,38,25,59,94,44,136,143,237,200,35,25,250,230,84,245,165,12,108,230,246,177,41,229,193,132,167,154,91,158,201,46'],
        expectedOutput: '0xfd2edffa,0x3ad10a43,0x2e524616,0x7b153043'
      },
      {
        input: ['196,226,105,35,14,241,178,251,186,213,20,180,187,105,169,96,117,22,71,107,199,112,81,136,244,248,35,80,150,236,126,91,207,231,126,221,216,48,217,146,5,237,70,192,86,240,32,204,6,103,55,205,215,136,86,204,128,121,28,23,101,154,114,52'],
        expectedOutput: '0xf601e3c1,0xee4a8c4f,0xa500f0d7,0x53cef83e'
      },
      {
        input: ['129,240,18,89,32,235,236,37,216,50,229,47,34,5,251,40,109,50,246,68,187,76,16,59,197,44,82,42,198,196,95,71,180,113,161,212,92,141,249,52,191,222,99,226,228,94,10,81,145,0,149,76,76,166,135,17,210,218,60,153,158,155,224,83'],
        expectedOutput: '0xe872ddba,0x215985c8,0x3ab3ddb7,0x6a7aca2a'
      },
      {
        input: ['12,129,39,104,14,33,156,206,255,0,176,227,94,186,52,239,187,202,59,7,112,195,25,66,157,85,219,59,240,188,142,252,61,182,100,76,215,0,26,214,0,202,186,95,132,238,78,63,184,138,71,40,77,96,107,234,181,70,37,165,2,180,161,64'],
        expectedOutput: '0x87ba3dea,0x3015814e,0x45e89fe6,0x0e73c5aa'
      },
      {
        input: ['106,5,140,65,5,166,23,6,112,209,101,244,192,179,52,120,61,123,161,138,219,12,116,144,82,154,53,85,78,214,149,184,219,33,249,224,199,16,230,55,226,75,43,162,255,95,26,60,218,187,199,181,199,59,69,26,213,122,111,35,80,4,219,43'],
        expectedOutput: '0x9de1aca1,0xeae307a5,0x247675c7,0xf39750da'
      },
      {
        input: ['37,212,12,236,229,242,35,199,62,78,105,61,174,131,121,136,63,64,62,6,124,131,32,81,254,143,117,78,147,80,122,184,37,134,164,10,120,199,209,182,22,58,243,196,189,109,76,252,173,138,3,41,14,35,123,12,179,240,90,70,64,212,255,101'],
        expectedOutput: '0x45751b81,0x05339fa3,0xab944e28,0xc6fd5c04'
      },
      {
        input: ['90,163,111,211,107,64,137,129,122,125,69,56,234,145,52,151,28,55,193,42,91,60,54,14,44,144,84,108,101,83,210,191,247,65,146,98,130,28,227,252,153,40,52,131,185,105,26,213,160,219,255,251,23,53,9,67,198,94,176,43,177,130,234,168'],
        expectedOutput: '0xe288a5c9,0x7f57a17d,0x9d6a5b68,0x4bfbd473'
      },
      {
        input: ['195,125,10,69,153,237,66,50,21,118,181,207,223,207,164,128,171,164,123,194,217,133,6,159,227,182,202,148,56,181,61,251,50,71,65,203,53,131,253,74,249,178,25,217,129,190,89,44,98,212,239,59,89,245,219,60,171,165,209,227,90,14,222,140'],
        expectedOutput: '0x9ce3159e,0x4d23eb50,0x52d1f688,0x23beaa8d'
      },
      {
        input: ['85,31,87,138,162,84,213,156,6,238,117,136,172,206,180,14,162,163,74,252,152,37,56,67,202,9,38,37,23,5,177,109,36,9,247,199,93,204,99,100,187,216,236,103,166,160,118,72,68,192,68,220,229,125,32,175,134,70,212,158,75,134,11,112'],
        expectedOutput: '0xb374efaf,0x6fb7fe6c,0xd65d9ffa,0xf8b9f2bf'
      },
      {
        input: ['143,2,55,236,207,154,80,138,114,60,241,24,221,103,96,33,39,165,253,12,34,29,188,168,100,144,70,175,22,81,31,165,84,86,146,35,240,226,173,98,31,158,122,252,6,219,29,45,128,26,58,162,56,246,74,156,134,145,75,157,226,107,66,54'],
        expectedOutput: '0xa5904203,0x78a9ce68,0x4d1f333a,0xa918baae'
      },
      {
        input: ['193,212,89,178,183,6,20,214,165,143,210,171,106,239,216,234,9,18,140,65,8,214,221,143,103,41,44,74,148,110,128,85,67,218,7,250,224,28,208,133,171,162,48,21,145,9,255,154,27,139,220,36,97,185,179,201,226,223,19,118,77,147,204,144'],
        expectedOutput: '0x17e4ba25,0xd779cc76,0x2fd8b4ff,0xbf2dde0a'
      },
      {
        input: ['109,211,138,78,239,90,211,154,252,4,175,141,13,174,40,40,57,4,76,155,189,255,100,160,222,119,22,44,10,226,188,120,182,71,198,165,161,153,64,158,157,239,43,170,158,83,211,215,87,31,114,21,31,214,181,253,77,203,41,88,174,230,208,100'],
        expectedOutput: '0x4d63b569,0xc6fa1d44,0xcf551c3e,0xfe72ae70'
      },
      {
        input: ['45,150,9,206,47,73,108,205,57,152,119,215,235,74,174,67,106,33,88,137,247,13,134,69,216,176,157,134,150,109,234,195,3,244,145,50,61,254,255,118,150,119,77,129,193,252,196,43,29,28,180,20,41,59,89,2,235,246,136,129,99,115,68,102'],
        expectedOutput: '0x3b85b6f7,0xaa5d75df,0xa7780927,0xc0c095f7'
      },
      {
        input: ['103,213,153,164,211,152,27,105,15,104,235,209,100,175,252,129,204,177,150,245,236,239,247,215,230,128,88,73,243,156,176,90,113,73,254,69,225,25,174,241,130,153,194,230,73,190,104,21,111,254,10,91,237,2,50,211,130,138,29,117,38,205,207,152'],
        expectedOutput: '0xc8bb028d,0xcee4e2db,0x905bcec6,0x26bcb0c3'
      },
      {
        input: ['22,205,221,247,231,139,232,105,37,170,79,110,105,183,131,216,181,141,52,163,143,102,118,17,241,147,134,23,96,85,175,118,35,140,110,10,24,86,115,61,1,194,171,106,122,46,66,47,187,118,210,75,221,73,92,206,220,227,229,61,56,149,179,91'],
        expectedOutput: '0x32773a5a,0x90830ee6,0x7f97b9d9,0x3ed38193'
      },
      {
        input: ['33,33,101,57,120,216,118,121,155,33,227,21,79,37,68,11,156,23,86,121,96,178,71,60,149,44,121,206,193,45,41,227,78,143,28,198,103,147,63,2,180,34,23,4,72,92,15,228,115,101,93,211,23,164,15,173,208,137,123,146,182,164,117,4'],
        expectedOutput: '0xf7a72e44,0x47fb5b47,0xff433ad4,0xa63fd1b3'
      },
      {
        input: ['51,145,203,155,36,10,157,217,45,181,221,117,17,236,89,132,81,182,87,104,90,102,21,42,239,144,188,165,53,49,170,104,195,117,3,231,127,161,192,172,86,157,33,103,137,122,235,218,48,66,67,138,168,88,181,152,233,113,61,30,163,231,134,102'],
        expectedOutput: '0xf8555c45,0x70eadd28,0xbda82241,0x520d9047'
      },
      {
        input: ['92,138,77,220,43,14,136,129,171,170,232,53,36,211,15,85,21,82,223,189,171,148,85,148,6,147,178,169,122,56,15,215,194,92,179,237,106,59,110,22,229,86,75,10,41,90,95,62,173,62,252,88,211,81,236,217,228,158,130,95,214,145,54,153'],
        expectedOutput: '0x5184670e,0x94b50ac9,0xad7f05a1,0xaac2a2fe'
      },
      {
        input: ['237,233,134,88,36,245,110,10,75,185,20,117,19,115,179,192,177,175,24,132,1,4,93,229,162,223,68,121,112,122,18,94,99,152,182,136,141,36,146,217,221,166,78,240,25,1,177,202,177,201,79,178,206,172,151,112,140,220,233,252,86,251,90,186'],
        expectedOutput: '0x6862efbf,0x9dbaf450,0xaf71703b,0xef819be9'
      },
      {
        input: ['148,16,66,33,52,212,250,17,122,72,2,147,74,179,93,251,124,172,173,74,89,68,187,229,32,164,225,119,160,60,49,52,76,115,85,129,71,80,146,193,152,148,84,226,71,177,221,196,94,138,14,183,207,201,156,239,110,125,102,14,185,151,66,6'],
        expectedOutput: '0x754a976c,0x1610ed02,0xca455d7f,0x41d311a3'
      },
      {
        input: ['10,151,135,81,231,25,18,128,174,102,98,245,24,64,185,118,202,200,45,153,145,201,137,255,70,239,13,0,135,79,6,145,231,141,227,206,166,245,78,84,92,177,74,116,241,3,234,187,203,23,85,93,224,222,92,38,205,106,38,84,185,44,230,160'],
        expectedOutput: '0x841647cf,0x58d43831,0xc3f9d91a,0xff656235'
      },
      {
        input: ['185,201,111,96,190,189,180,26,110,254,142,95,2,120,27,205,143,112,42,111,78,135,150,27,241,188,112,170,233,86,75,162,31,186,2,221,119,183,248,230,181,134,69,183,255,96,133,142,208,175,254,30,54,148,58,39,80,170,210,57,0,29,220,31'],
        expectedOutput: '0x4a663398,0x24fc2fdc,0xb0ac3ba4,0x2a49aed2'
      },
      {
        input: ['215,222,252,78,149,244,52,75,123,122,2,122,218,135,8,171,55,6,201,109,154,3,149,235,173,103,36,173,132,0,204,91,223,201,169,116,189,222,191,56,88,194,178,50,73,187,221,128,193,167,238,92,170,131,71,88,234,107,5,110,108,210,201,75'],
        expectedOutput: '0xb5d38bfd,0xb22e6654,0x5ee175f5,0xfc488340'
      },
      {
        input: ['155,114,191,88,80,127,145,168,65,67,219,138,254,184,11,192,95,249,28,10,124,99,98,102,206,103,212,58,57,157,133,212,15,69,45,96,196,190,8,5,1,227,143,0,156,154,192,251,147,220,5,15,63,103,117,13,207,73,72,8,230,205,221,246'],
        expectedOutput: '0x878fda53,0x3f01f782,0xae4fb2ad,0xfd1a710d'
      },
      {
        input: ['18,10,86,214,200,94,219,201,66,107,201,222,5,137,217,153,101,223,168,164,70,30,178,21,103,250,30,78,199,251,68,218,5,154,176,205,248,140,150,58,247,96,24,252,233,242,149,79,209,62,243,23,92,165,45,195,159,75,17,103,70,85,65,75'],
        expectedOutput: '0x4907da77,0xc0debe45,0x75e6349c,0xb158f328'
      },
      {
        input: ['239,241,24,232,125,174,34,116,14,59,113,248,45,6,71,254,68,58,21,160,224,66,100,127,141,117,230,211,203,39,30,186,25,54,162,150,229,197,11,243,0,124,235,45,130,50,43,199,109,64,103,77,131,203,204,16,65,179,228,12,218,2,198,243'],
        expectedOutput: '0x2538d629,0xbd7997c4,0xa63c0b52,0x91a55332'
      },
      {
        input: ['57,105,138,30,46,149,17,46,17,253,91,147,47,134,90,156,198,194,233,73,141,182,90,206,105,62,218,67,64,161,55,121,10,193,151,56,86,169,102,103,166,193,250,213,71,85,114,13,23,91,87,164,17,177,115,122,239,77,190,47,238,245,169,248'],
        expectedOutput: '0x2069a123,0xedc88d08,0xc36d3437,0xeff328b9'
      },
      {
        input: ['182,64,48,12,233,150,115,143,87,109,101,158,194,215,172,217,50,3,126,68,180,241,190,163,62,124,210,45,113,123,37,39,188,86,51,165,236,166,53,68,20,154,226,214,113,142,176,163,145,46,231,69,31,166,232,93,34,187,138,148,54,176,187,242'],
        expectedOutput: '0x4df90900,0xfd4b28fa,0x6a408d16,0x9398595d'
      },
      {
        input: ['6,239,152,242,149,205,54,169,103,25,128,216,167,48,123,57,94,99,126,125,9,103,218,43,34,101,191,88,21,123,75,27,106,227,13,255,176,68,169,23,93,41,239,4,89,106,61,183,205,188,52,214,35,14,2,69,115,193,157,136,60,232,163,166'],
        expectedOutput: '0x038d794c,0x93454ee1,0xe59d5b48,0xd0ed69c8'
      },
      {
        input: ['203,177,166,123,245,79,146,82,120,129,86,209,236,148,136,185,80,188,144,115,202,146,184,62,83,85,198,144,62,106,54,9,27,220,133,16,43,23,98,163,153,184,116,133,76,252,62,156,184,206,15,131,96,199,193,180,29,135,68,91,241,122,100,12'],
        expectedOutput: '0x8653840d,0x975a3883,0x1c65d8f7,0x96816777'
      },
      {
        input: ['87,233,28,130,1,126,38,154,55,154,31,131,151,93,32,79,44,47,210,140,247,147,64,20,27,132,111,12,255,211,25,86,189,53,216,190,180,254,88,235,153,119,110,48,212,142,127,0,190,82,141,181,229,205,201,0,82,56,13,81,11,38,167,200'],
        expectedOutput: '0xf2ceb7b0,0x8168e267,0xf54a863c,0xf2a10343'
      },
      {
        input: ['91,127,134,15,126,222,250,23,85,105,71,42,247,198,42,181,24,183,106,254,133,51,254,215,107,11,40,119,49,207,63,141,78,198,156,204,164,151,227,250,0,42,36,247,241,78,173,9,6,23,7,139,75,6,98,182,17,138,45,67,89,109,208,167'],
        expectedOutput: '0x9f04f8da,0x399ce41b,0xe0dee381,0xfcc9f178'
      },
      {
        input: ['51,108,116,215,3,87,209,3,130,245,251,115,68,168,124,74,191,132,213,10,138,55,193,155,193,238,222,26,91,174,193,142,27,53,102,30,141,55,34,15,45,29,130,113,197,254,187,132,130,144,143,12,199,80,168,136,62,134,162,154,53,99,40,80'],
        expectedOutput: '0x36954414,0x19eb95a9,0x45d93a5a,0x5b461f40'
      },
      {
        input: ['153,142,110,38,198,144,53,243,173,183,100,114,181,31,247,56,175,134,68,118,214,236,254,20,115,160,174,168,3,215,248,156,101,102,194,43,247,247,30,164,174,130,23,100,161,14,156,80,148,224,198,106,205,196,126,64,100,45,232,104,4,224,4,105'],
        expectedOutput: '0x70e69649,0x06dd6ee5,0x61b691fa,0xf4c566be'
      },
      {
        input: ['70,199,149,61,190,179,226,109,54,249,209,215,7,109,40,155,77,238,5,26,179,131,90,23,176,66,127,180,34,132,30,105,75,179,166,9,102,136,118,156,129,71,116,136,180,156,35,2,138,40,28,61,172,119,85,92,185,212,17,220,88,47,69,163'],
        expectedOutput: '0xf513144d,0x6adb0f24,0xaf58138a,0x916486f4'
      },
      {
        input: ['226,235,173,72,116,35,229,245,107,89,126,31,245,161,33,127,202,62,189,118,181,18,210,110,230,227,74,63,18,143,226,244,123,143,61,239,179,34,228,30,123,98,61,112,4,95,239,206,157,172,68,82,190,22,192,165,250,11,228,12,154,198,1,21'],
        expectedOutput: '0x0b5e067e,0xae942402,0x2182998a,0x77da0da8'
      },
      {
        input: ['86,62,4,9,96,233,39,219,75,100,75,79,195,58,29,96,231,97,178,165,120,115,74,114,126,46,126,24,245,127,46,75,189,50,84,29,27,123,248,103,223,67,182,163,126,212,3,101,53,182,10,173,41,85,31,167,131,158,191,120,29,237,195,219'],
        expectedOutput: '0xd3f0e09a,0x5a42f45f,0x14dc4756,0x18f2536e'
      },
      {
        input: ['32,23,248,59,146,241,162,114,52,89,21,178,45,24,23,98,206,34,16,247,119,47,158,250,205,94,115,235,75,54,198,107,78,190,167,224,175,73,82,228,162,103,150,207,128,174,50,78,208,66,70,71,113,228,65,63,66,180,42,142,235,240,249,57'],
        expectedOutput: '0x0776aa4b,0x429577a7,0x229dbc46,0x45273185'
      },
      {
        input: ['174,160,25,94,234,108,66,140,211,216,92,83,134,142,162,86,208,232,157,65,204,223,128,15,147,170,157,126,154,150,183,73,55,209,167,33,61,233,173,16,193,9,100,72,151,6,158,103,238,60,169,186,27,41,201,174,212,102,45,110,253,228,183,52'],
        expectedOutput: '0xe381d716,0x147b3223,0xd3761aa0,0x66da94a9'
      },
      {
        input: ['181,94,85,242,71,2,3,9,12,103,81,163,109,239,11,91,43,180,21,70,221,223,245,177,69,34,32,66,6,215,118,188,54,203,174,125,206,177,134,218,24,215,125,133,199,136,224,242,60,246,57,26,213,46,203,26,80,235,93,86,195,211,18,249'],
        expectedOutput: '0x25af8e91,0xb7526c5f,0x767072d7,0xc9718378'
      },
      {
        input: ['159,193,118,109,114,253,71,139,212,196,16,155,77,241,142,137,231,199,163,188,245,111,214,69,90,51,155,29,7,174,22,166,111,141,19,225,138,90,108,94,30,125,250,107,110,136,245,85,79,152,17,68,7,231,137,98,27,36,127,34,210,150,200,65'],
        expectedOutput: '0x6f1f98fc,0xf3fb6a6e,0xe12e74c3,0xea8010f3'
      },
      {
        input: ['35,219,35,173,53,143,11,83,12,5,191,122,141,180,207,220,76,224,32,84,200,169,182,227,206,53,5,160,203,205,226,238,168,5,155,221,148,167,48,161,172,239,27,58,163,235,22,240,203,55,68,147,224,250,118,174,47,123,79,251,72,49,233,240'],
        expectedOutput: '0x03f1d226,0x0fbcbb7c,0x21142896,0x47c152fa'
      },
      {
        input: ['54,133,205,202,44,254,107,216,237,135,18,145,114,41,129,61,96,197,209,64,191,71,239,238,195,62,233,11,111,211,252,165,88,201,111,132,199,219,92,181,98,111,70,212,152,199,17,248,140,226,56,75,42,39,57,237,101,35,248,212,246,244,121,78'],
        expectedOutput: '0x72c249e5,0x0234b7c5,0xd5724be2,0x31242510'
      },
      {
        input: ['190,233,210,133,196,46,58,38,157,128,250,53,71,11,45,211,238,102,30,24,141,88,5,243,123,253,199,113,242,65,191,176,42,145,53,238,191,112,20,93,240,14,146,56,25,192,11,7,38,42,31,179,130,36,166,253,34,110,110,20,175,45,196,217'],
        expectedOutput: '0x04bb7eb7,0xc76da4b5,0x772d9797,0xee35153d'
      },
      {
        input: ['190,249,199,125,105,219,218,90,233,109,146,2,45,157,10,83,199,41,6,73,78,173,70,112,27,180,132,202,225,72,163,159,65,106,29,171,69,247,5,46,100,151,48,145,52,58,228,252,100,235,69,178,152,140,34,179,64,166,125,34,238,32,193,47'],
        expectedOutput: '0x2810a232,0xe2ae8d0e,0x547c1436,0x30cc976e'
      },
      {
        input: ['138,222,218,207,214,223,253,58,118,45,204,171,104,176,167,204,155,236,126,51,120,160,230,185,70,99,219,52,131,156,99,13,123,62,220,81,29,217,139,148,7,87,63,111,8,230,59,163,210,185,215,75,89,189,4,159,33,223,211,164,123,54,178,246'],
        expectedOutput: '0xab8ab237,0xdd514e5e,0x53fc4603,0x77d0def2'
      },
      {
        input: ['116,142,71,146,104,211,38,111,42,101,222,50,75,25,214,29,210,173,104,43,106,108,202,139,75,157,48,199,211,226,189,72,112,5,218,216,216,0,71,2,101,37,53,176,62,11,205,16,184,54,59,34,162,5,174,238,162,222,181,118,192,114,190,48'],
        expectedOutput: '0xd4e5034b,0xde3ae043,0x9474f1c8,0xe06269a4'
      },
      {
        input: ['119,152,9,79,152,80,82,253,118,135,173,180,146,122,197,74,176,0,108,83,6,26,65,168,248,246,30,184,104,220,233,224,116,242,47,12,66,129,9,184,8,182,109,154,49,50,228,225,50,81,52,56,107,117,225,100,107,255,28,212,220,5,180,80'],
        expectedOutput: '0xf775ab7d,0x1f8ec2f6,0x5b66e0a0,0x0d0e9a9d'
      },
      {
        input: ['247,227,93,58,101,102,242,109,29,95,8,78,145,236,47,196,61,100,252,169,217,221,13,69,221,41,25,185,47,205,9,38,176,102,96,21,205,83,131,234,178,139,56,68,119,103,8,181,203,4,94,165,226,107,234,191,148,3,120,195,208,129,234,128'],
        expectedOutput: '0x9172c5d8,0x28186f8d,0x10417a22,0x25a8bd81'
      },
      {
        input: ['232,74,150,181,157,25,159,80,164,215,148,27,62,156,208,10,160,46,175,130,153,153,65,46,156,185,241,108,59,219,236,35,38,130,216,195,155,119,19,63,78,167,91,140,67,43,150,228,90,69,102,243,222,168,33,122,97,19,230,156,238,211,191,20'],
        expectedOutput: '0xeb9c96a1,0x2f14c6f5,0xa40b81e4,0x30423d67'
      },
      {
        input: ['85,151,216,241,14,235,48,92,147,139,233,214,183,127,186,17,197,33,4,163,201,38,30,42,57,4,199,39,215,134,60,45,30,20,30,44,255,78,137,146,218,114,105,145,241,35,162,182,68,166,90,13,204,120,56,5,124,255,45,84,133,105,129,163'],
        expectedOutput: '0xbe608995,0x8697c8a3,0x2ebdd538,0xb3e7435f'
      },
      {
        input: ['125,159,208,124,237,89,15,199,203,120,88,188,155,250,115,224,161,205,237,109,69,37,115,193,36,160,21,170,9,150,77,134,53,29,2,35,118,17,234,65,137,67,254,37,61,113,5,222,62,242,76,131,24,191,68,60,95,90,230,104,240,52,238,38'],
        expectedOutput: '0x5f494afe,0x52ba6a70,0xb434aa79,0x36145c91'
      },
      {
        input: ['81,240,73,200,2,51,9,139,118,7,176,180,120,181,146,182,168,222,57,192,157,126,252,252,216,227,100,200,23,82,238,104,67,55,48,69,107,58,208,225,65,129,149,186,54,40,112,222,6,170,158,164,40,155,160,0,126,5,200,149,87,183,253,154'],
        expectedOutput: '0xa6352f30,0xce93b656,0xba81b8aa,0x4f1c0ca9'
      },
      {
        input: ['238,46,223,89,104,176,59,169,49,208,99,103,248,212,70,255,126,228,163,166,127,67,166,253,72,110,146,160,37,144,58,20,190,26,109,38,202,168,207,251,121,51,98,113,7,168,112,133,141,19,43,12,87,209,10,159,63,156,63,101,44,122,121,234'],
        expectedOutput: '0xe4abe782,0xac450821,0x6e88dcdf,0x0f943a1f'
      },
      {
        input: ['148,230,16,94,143,224,89,8,19,187,121,26,100,234,159,241,253,202,253,84,155,7,244,218,164,51,63,208,173,184,187,65,159,203,159,46,171,248,54,190,180,175,216,24,153,119,9,151,65,6,235,220,14,223,183,178,19,246,130,192,175,61,2,78'],
        expectedOutput: '0xcf028ac6,0x2c1952f6,0x8b674be8,0x020e49f8'
      },
      {
        input: ['9,161,124,180,154,178,115,78,97,75,102,251,195,111,146,4,117,125,225,131,93,152,53,112,142,184,48,61,245,50,139,254,212,7,179,110,185,38,188,27,113,34,22,52,145,168,57,6,37,26,138,130,178,191,242,64,119,35,126,109,85,9,107,41'],
        expectedOutput: '0x20629c9c,0xdd715d48,0x35acfe35,0x6150b1d5'
      },
      {
        input: ['17,30,151,202,68,83,229,182,117,251,234,6,163,35,13,201,61,151,75,239,86,62,48,206,97,174,59,182,183,166,224,200,197,119,147,9,203,120,191,64,116,170,71,23,205,84,224,11,235,44,250,65,106,42,15,203,216,74,129,144,241,97,88,182'],
        expectedOutput: '0x0478dd5a,0x46e90e56,0xe46dc590,0xbdb887f8'
      },
      {
        input: ['217,235,191,164,100,127,228,216,41,43,239,246,127,208,1,106,252,252,172,102,38,187,49,255,6,178,143,247,20,231,173,237,211,108,145,55,235,117,15,20,161,254,11,32,206,12,139,202,8,55,48,47,242,97,46,248,20,189,239,40,164,156,21,119'],
        expectedOutput: '0x4460b5d2,0xdd0e7927,0x12c9faee,0x03cd56fe'
      },
      {
        input: ['9,166,174,244,27,189,9,188,188,20,221,138,32,104,85,41,159,133,88,145,231,134,138,251,67,121,35,231,22,56,95,31,222,13,19,249,203,28,182,135,48,147,17,81,251,102,122,154,236,210,43,211,88,181,206,155,47,241,130,69,41,225,100,7'],
        expectedOutput: '0x6dade15b,0x650ac08f,0xcec325e5,0x36efb013'
      },
      {
        input: ['239,119,0,186,148,182,65,196,73,82,21,68,185,143,222,165,97,10,120,185,191,70,84,238,55,215,51,96,184,151,103,167,15,103,97,163,30,162,103,103,245,125,172,174,12,138,83,110,148,203,39,84,17,124,66,72,83,118,168,11,13,15,179,28'],
        expectedOutput: '0x646f8525,0x18f1eb02,0x4042c85c,0x7e9b7135'
      },
      {
        input: ['118,20,191,148,183,39,252,172,164,168,90,176,50,173,30,199,120,70,27,137,194,93,209,21,211,121,32,225,136,211,253,254,232,189,147,159,228,143,75,136,55,165,56,105,82,87,48,202,157,75,83,95,169,36,116,124,157,148,93,37,104,91,35,80'],
        expectedOutput: '0xf4b6a8d7,0xe3c42c74,0xb21936a3,0xdcc68662'
      },
      {
        input: ['24,182,239,252,69,58,132,124,223,188,230,49,19,22,251,176,98,78,15,11,114,131,135,15,24,229,52,128,64,87,208,88,14,191,84,83,249,216,208,216,148,182,9,168,204,4,88,46,82,104,57,196,235,193,211,3,166,7,131,230,94,83,62,108'],
        expectedOutput: '0x632f7a27,0xb31532ab,0xb08a24fa,0xe72c3dfd'
      },
      {
        input: ['18,146,192,11,106,144,227,254,70,236,166,18,240,255,65,66,103,122,6,82,59,217,86,225,224,217,199,63,45,5,171,63,151,107,75,1,251,46,0,65,27,166,84,11,165,149,78,12,15,84,95,75,46,181,44,14,142,244,77,187,249,249,251,145'],
        expectedOutput: '0x2e30b32e,0x0bf753e3,0xd1ec5467,0x0f442994'
      },
      {
        input: ['100,70,146,96,116,146,161,143,57,245,155,222,138,233,235,154,61,74,229,107,255,17,122,141,5,199,73,255,192,68,144,37,138,34,133,254,181,38,142,238,28,41,204,166,18,183,64,79,1,37,187,0,55,53,142,60,252,215,59,189,27,203,226,165'],
        expectedOutput: '0xe582965b,0xe2792187,0x8b347ab5,0xe8d37827'
      },
      {
        input: ['238,103,163,163,141,49,145,169,90,93,80,108,21,144,188,22,182,119,23,237,172,165,41,168,124,101,101,151,48,71,60,30,174,223,193,60,17,82,229,107,176,53,216,197,198,148,219,124,11,242,105,183,151,146,95,19,247,197,170,40,12,230,70,187'],
        expectedOutput: '0x14d0ed81,0x69a860d7,0x27c2964b,0xd4dd8d1a'
      },
      {
        input: ['198,8,247,215,90,220,66,10,18,26,207,216,174,171,84,185,157,189,112,53,79,208,72,71,149,243,111,161,217,181,92,159,189,83,118,24,48,185,34,66,211,242,26,130,157,110,59,58,43,172,111,122,124,184,193,17,171,48,178,132,230,15,36,163'],
        expectedOutput: '0x9e893b9d,0x9990efff,0xbadcff5f,0x9cfc0403'
      },
      {
        input: ['98,154,187,146,83,222,212,39,208,238,169,109,92,228,167,135,144,23,2,12,207,195,29,122,244,208,254,218,223,34,125,65,189,57,212,16,23,168,55,231,151,224,84,243,197,251,123,85,18,125,98,225,64,127,91,52,79,90,14,46,124,140,112,57'],
        expectedOutput: '0xaa392263,0xbfd7c8e7,0x7075a82b,0x4f4c22b6'
      },
      {
        input: ['197,68,74,220,236,129,195,131,98,23,119,39,18,242,124,37,111,222,6,175,94,98,228,173,188,242,220,56,126,76,114,67,144,188,31,124,61,226,0,159,249,119,198,12,105,67,49,216,33,55,135,127,153,107,45,85,94,9,142,220,85,0,32,229'],
        expectedOutput: '0x4722f525,0x2d445072,0x0dff468b,0xd9d388fe'
      },
      {
        input: ['188,63,97,249,34,97,153,27,216,95,39,65,162,88,25,196,144,161,67,41,12,112,127,106,121,13,71,206,13,103,179,201,166,21,194,200,118,91,228,79,187,11,144,93,100,170,33,244,75,101,29,87,213,156,194,79,169,9,29,182,112,209,127,22'],
        expectedOutput: '0x4f93915a,0x7850cb27,0xf6e5301e,0xbba3f7c7'
      },
      {
        input: ['230,66,223,92,157,195,171,88,206,60,182,50,230,215,38,49,60,68,136,18,224,74,97,138,83,126,64,195,79,192,218,53,2,185,146,159,124,61,248,74,121,174,125,95,133,163,144,194,231,25,212,200,99,53,82,183,179,146,122,3,82,84,56,84'],
        expectedOutput: '0x1ec8ff9e,0x360aa7a9,0x2a5ea15d,0xd4d1e456'
      },
      {
        input: ['13,202,244,137,8,236,212,129,154,81,225,31,244,113,225,220,138,181,164,238,234,246,165,158,136,31,161,219,116,217,47,129,164,35,11,172,15,223,45,169,48,14,201,36,128,170,0,10,96,164,248,74,154,157,232,35,189,137,254,49,99,45,178,7'],
        expectedOutput: '0x689453c7,0xba12987b,0x14289191,0x3d240155'
      },
      {
        input: ['81,189,179,96,156,224,10,204,239,211,241,111,125,241,121,221,150,114,40,48,15,16,83,204,154,81,253,253,127,176,4,208,109,183,48,10,151,58,214,134,13,199,245,139,185,111,104,79,225,144,127,240,161,211,189,59,36,186,56,163,106,60,115,216'],
        expectedOutput: '0x89ca93b6,0x8d6c0df0,0x600805d6,0x2a2a4374'
      },
      {
        input: ['243,164,226,138,222,184,17,236,128,6,119,57,117,223,136,86,112,7,71,17,218,4,76,255,190,132,162,41,192,22,1,179,186,227,61,152,155,78,132,27,85,251,84,202,219,220,33,75,228,104,92,190,108,168,189,42,44,96,83,236,118,84,159,48'],
        expectedOutput: '0x5fe990b7,0xc3924099,0xb88fd9e6,0x35dc87e7'
      },
      {
        input: ['55,220,200,211,43,77,238,128,72,67,74,35,31,107,110,3,211,202,194,63,114,127,106,158,223,189,138,85,18,41,133,73,6,78,28,49,155,11,177,227,78,251,7,109,103,117,113,58,64,51,122,178,178,228,81,146,161,219,231,179,5,109,253,11'],
        expectedOutput: '0x7d430840,0x14071439,0xc6954452,0x3c847672'
      },
      {
        input: ['187,25,60,86,36,237,57,114,232,64,224,79,182,81,138,246,132,4,168,54,232,249,200,137,213,176,61,218,29,58,229,216,83,33,46,120,14,103,234,246,168,202,70,94,27,208,84,159,212,252,214,188,246,158,69,203,78,130,165,107,188,138,67,16'],
        expectedOutput: '0xc0a7c592,0xc69a0e33,0x12fbbd6b,0xb00f64c6'
      },
      {
        input: ['171,113,136,185,217,114,175,129,61,245,223,88,197,51,248,153,47,206,85,37,108,155,240,187,29,149,38,218,31,106,234,202,219,114,131,180,228,51,53,33,40,20,122,238,71,114,135,119,64,221,156,172,120,141,103,149,34,142,111,66,248,89,12,211'],
        expectedOutput: '0x9f50f0b4,0x4f64d543,0x30e76cb7,0xcea2afdd'
      },
      {
        input: ['203,144,136,176,195,189,209,235,210,75,217,25,189,97,144,253,62,45,170,182,186,17,75,220,159,187,30,151,20,43,107,224,187,243,144,126,176,97,105,130,173,67,156,106,164,44,104,226,89,18,152,19,35,227,240,195,158,14,90,179,57,197,147,244'],
        expectedOutput: '0x657a5572,0x1a87e3bf,0xffbc2535,0x28592100'
      },
      {
        input: ['184,35,114,105,132,220,235,49,31,135,156,195,180,4,165,13,22,61,33,57,32,17,252,191,31,87,114,89,28,5,77,213,40,192,62,172,156,41,222,187,177,122,126,101,126,35,114,148,96,147,205,128,164,202,63,196,33,177,29,61,182,106,18,222'],
        expectedOutput: '0x3cca90f5,0x6f9ae7a9,0xfb9d1837,0x6bd579be'
      },
      {
        input: ['42,80,139,198,122,105,129,43,227,255,144,97,34,2,245,130,150,194,3,58,140,66,254,173,244,27,235,170,134,253,137,176,78,20,119,200,125,248,243,96,248,131,193,26,133,182,157,27,120,160,86,5,226,84,178,214,112,157,129,246,155,10,166,233'],
        expectedOutput: '0xc2ee46aa,0x31295362,0x2514562f,0xb0fd1240'
      },
      {
        input: ['30,29,177,155,22,164,251,14,39,188,40,172,114,197,200,234,101,30,239,72,114,162,30,226,63,159,216,218,169,127,195,199,156,116,98,178,24,93,192,63,25,233,236,139,174,180,118,20,210,101,92,68,7,122,39,71,26,255,33,195,126,229,139,27'],
        expectedOutput: '0xbd490471,0x8648f73a,0x69b74649,0xa543260f'
      },
      {
        input: ['89,237,205,114,75,142,177,100,119,157,240,37,81,102,57,35,203,149,104,211,16,143,26,42,142,59,237,13,32,120,40,122,102,245,236,177,131,157,21,250,59,5,32,140,107,89,176,55,239,24,10,255,167,36,41,53,95,22,66,128,143,106,250,245'],
        expectedOutput: '0x05d02c68,0x368f2ee5,0x8f69ea98,0x93aa8915'
      },
      {
        input: ['96,230,166,227,131,187,222,190,193,254,75,44,87,251,99,70,19,109,69,186,145,110,239,241,133,50,113,20,156,107,9,252,81,175,224,212,106,190,147,43,188,222,88,19,217,187,90,236,41,159,166,186,14,149,171,147,199,28,167,100,135,176,96,216'],
        expectedOutput: '0xace5ca68,0x5aec9e92,0x35e7f8da,0x1bdeb062'
      },
      {
        input: ['95,64,173,201,254,64,245,186,30,77,206,247,8,40,227,49,199,137,236,213,30,151,104,230,180,15,74,59,191,170,20,30,235,193,232,233,1,221,164,31,42,114,22,50,154,249,100,97,130,80,55,160,231,159,134,155,175,208,215,110,123,235,141,102'],
        expectedOutput: '0x8102f104,0x03c821b4,0xdb8a0763,0x034e3abc'
      },
      {
        input: ['172,117,79,173,82,243,204,124,101,226,174,255,219,18,97,93,98,152,253,74,55,132,229,230,84,188,85,207,167,226,53,83,87,133,0,169,120,204,37,222,174,211,221,137,230,62,230,72,214,228,146,14,104,120,244,188,52,73,140,220,43,193,47,130'],
        expectedOutput: '0x4f299878,0x04c3c3bf,0xa95fac6c,0xd65aca6c'
      },
      {
        input: ['70,48,43,191,252,80,157,171,36,122,52,10,185,27,82,143,255,229,157,103,93,146,35,145,219,175,109,7,113,157,137,183,205,181,118,201,5,19,116,41,142,169,51,71,196,134,214,195,107,116,42,200,6,77,89,225,253,199,232,110,100,114,37,49'],
        expectedOutput: '0xe37f62a1,0x98cb4e49,0xe4d3efd2,0xd21e77cb'
      },
      {
        input: ['39,156,250,44,175,111,86,61,24,137,132,220,15,91,159,122,207,201,66,213,22,156,182,19,99,159,129,199,17,167,248,56,67,242,100,242,97,186,48,121,68,180,85,83,15,244,206,222,189,16,179,212,172,106,231,15,9,105,214,26,16,206,82,83'],
        expectedOutput: '0x19f43636,0x3a4b02f7,0x2538be6f,0x33f09c7f'
      },
      {
        input: ['193,182,69,34,113,117,156,181,42,241,8,57,230,214,24,163,231,203,119,147,53,95,163,62,200,121,88,216,72,170,43,9,97,112,43,210,230,199,135,16,185,143,73,159,102,97,66,77,45,186,224,98,25,131,161,225,253,249,185,69,164,228,78,5'],
        expectedOutput: '0x279e63bf,0x784da284,0xbf8d9c06,0xfd3e2e64'
      },
      {
        input: ['84,121,215,58,65,94,74,250,237,148,153,83,245,219,160,34,149,129,133,174,4,38,143,1,31,72,70,195,44,148,200,129,14,159,187,79,253,6,73,235,154,226,62,143,189,223,178,83,96,55,1,100,93,145,102,124,217,172,64,6,65,8,135,79'],
        expectedOutput: '0x902543d7,0x39f0e625,0x5c660e33,0xf8d15661'
      },
      {
        input: ['168,66,158,165,72,231,144,226,201,207,114,134,174,36,217,14,91,219,114,184,108,216,52,69,133,116,75,198,125,210,21,37,21,179,202,93,154,91,64,99,42,178,233,216,214,195,230,49,158,88,233,10,49,29,79,182,146,155,124,15,109,145,52,130'],
        expectedOutput: '0xe5f5409f,0x02ee0782,0xfa157ea0,0xeeb86c49'
      },
      {
        input: ['68,254,224,222,89,32,65,131,210,42,91,168,237,65,217,139,154,194,149,203,223,229,129,113,128,253,128,237,142,180,112,210,179,80,176,12,112,241,144,66,27,235,234,9,45,195,148,199,133,42,146,100,15,19,214,143,16,86,124,158,11,236,112,190'],
        expectedOutput: '0x81b6a481,0x696ccc6d,0xff3fb74c,0x1168cf66'
      },
      {
        input: ['60,32,202,172,17,90,238,44,70,216,53,115,155,202,58,32,244,204,133,3,223,91,146,239,177,14,141,188,251,253,122,55,29,69,228,46,159,210,90,229,171,144,88,70,90,146,103,78,94,236,81,61,71,227,44,248,241,185,181,236,182,47,36,211'],
        expectedOutput: '0xd18b2373,0x4762b31f,0x736e57f1,0xdab07b86'
      },
      {
        input: ['116,8,1,20,218,92,249,133,236,82,204,70,228,51,148,67,31,229,128,102,200,173,94,185,102,19,166,29,67,202,240,183,210,242,203,172,78,197,50,58,23,254,128,251,49,20,62,80,249,191,182,193,108,20,122,210,40,32,239,107,234,224,34,188'],
        expectedOutput: '0x4b3e7717,0xd71cb590,0x7b136168,0xbe1d1e60'
      },
      {
        input: ['210,238,105,32,179,155,90,202,153,218,197,202,238,4,26,231,195,208,168,47,228,34,1,12,67,241,119,45,209,154,234,163,136,83,195,59,238,29,5,135,247,202,81,229,206,107,204,145,59,116,192,31,150,194,44,217,179,163,7,132,61,241,39,197'],
        expectedOutput: '0x908ad193,0xa3762de6,0xa7203b09,0x7ac38230'
      },
      {
        input: ['68,234,0,50,7,5,185,254,208,10,227,158,117,175,48,176,35,240,207,185,178,251,147,101,159,154,233,220,139,16,162,207,250,162,1,1,168,186,255,120,196,226,22,57,145,70,233,180,55,184,110,233,180,1,79,83,155,56,47,38,73,209,245,67'],
        expectedOutput: '0x7ef0d3d9,0xc1b43053,0xb63636f9,0x796892b8'
      },
      {
        input: ['116,246,69,28,176,68,148,116,39,170,173,184,241,150,109,40,78,219,17,2,220,96,85,119,153,133,157,226,86,146,37,202,136,106,230,56,175,122,172,214,37,89,142,22,239,251,62,61,214,79,64,178,176,149,41,73,26,198,43,113,88,80,59,224'],
        expectedOutput: '0x8ad093c1,0x028202af,0x6b60a1ab,0x447cd474'
      },
      {
        input: ['187,34,24,106,156,196,64,193,29,206,215,12,202,21,74,160,101,138,83,21,31,124,94,58,67,137,171,155,217,230,124,148,8,148,254,165,89,62,102,118,13,62,131,215,83,205,119,184,87,202,205,118,71,43,176,138,180,91,37,142,66,161,34,74'],
        expectedOutput: '0x42d251ab,0x48ffeee7,0x906aaaba,0x0fc0c0fa'
      },
      {
        input: ['54,33,239,143,95,86,5,108,148,136,67,231,85,187,160,172,133,109,35,204,153,211,86,77,47,124,219,113,29,254,187,83,31,171,226,126,1,232,235,149,112,46,124,198,233,28,114,111,138,149,59,35,105,146,112,152,14,76,9,43,74,196,127,105'],
        expectedOutput: '0x047d2de0,0x0b7416b3,0x1b2760a3,0xeb6332f4'
      },
      {
        input: ['111,97,231,112,73,210,5,186,1,130,128,234,158,242,89,40,136,149,75,241,39,188,137,53,8,146,96,82,86,223,187,198,65,162,54,138,117,60,68,118,190,196,96,92,183,186,133,63,79,208,48,118,140,185,171,148,75,11,230,161,235,161,103,44'],
        expectedOutput: '0x96c67c90,0x240630eb,0xae5d701e,0x32630904'
      },
      {
        input: ['68,158,182,185,218,251,47,152,191,143,244,118,73,121,181,152,74,229,14,214,158,185,107,233,197,81,139,176,243,242,220,55,144,146,240,106,141,31,2,77,174,247,195,248,112,121,144,186,94,159,145,253,88,252,230,29,77,113,205,64,100,169,119,244'],
        expectedOutput: '0x26fb5719,0xd4a0f1fe,0xcec25177,0xacaeb843'
      },
      {
        input: ['60,103,95,201,134,97,22,53,88,218,45,201,83,189,131,177,92,20,174,181,16,149,210,94,6,160,158,106,73,22,95,133,125,190,79,4,31,101,57,120,63,102,65,146,35,196,68,128,217,242,53,233,135,7,71,142,167,230,248,241,252,87,118,121'],
        expectedOutput: '0xd7bd6c10,0x0d051ce2,0x45493f32,0x43552281'
      },
      {
        input: ['21,197,125,53,43,182,173,106,28,238,253,64,178,65,192,139,51,245,117,187,252,188,73,164,162,65,149,158,153,11,24,174,209,149,227,252,76,144,102,104,126,99,168,49,164,104,188,216,93,49,147,90,238,220,254,144,29,147,47,182,158,71,101,111'],
        expectedOutput: '0x8c03f034,0x6046c256,0x285cf821,0xabb0d9fd'
      },
      {
        input: ['220,72,107,40,217,210,145,87,53,57,136,218,162,69,178,255,118,69,89,100,33,87,245,62,234,36,245,137,107,90,248,71,162,100,112,123,54,1,211,107,58,91,69,220,160,247,220,23,60,53,123,93,141,112,156,119,148,145,0,255,235,249,71,141'],
        expectedOutput: '0xc94a7e32,0xf868628b,0x1cb53f98,0xd875982c'
      },
      {
        input: ['93,183,9,147,184,220,254,242,55,68,207,216,59,171,239,120,224,106,213,109,219,113,229,111,2,229,111,237,222,182,123,59,109,132,206,37,96,205,23,151,17,230,111,76,145,94,196,114,201,154,223,164,11,196,19,14,170,130,251,136,56,118,196,165'],
        expectedOutput: '0xc6122175,0x6a51cde1,0xe461f0bf,0x2a7dc220'
      },
      {
        input: ['250,146,202,90,95,226,242,112,200,97,189,90,192,129,204,137,27,171,45,39,112,64,53,26,195,48,162,251,167,102,161,161,249,107,252,88,77,238,201,22,79,134,112,15,7,60,152,35,231,197,74,87,6,127,113,201,175,20,196,86,122,101,248,115'],
        expectedOutput: '0x0576538f,0x92194428,0xf6e22812,0x66d634f4'
      },
      {
        input: ['209,244,204,30,226,149,52,49,27,164,65,34,224,217,69,200,159,143,31,165,14,145,110,190,165,50,20,31,152,12,147,105,0,95,135,226,244,188,20,15,96,85,49,65,46,119,9,205,6,40,114,21,185,224,211,94,19,231,126,171,244,17,20,244'],
        expectedOutput: '0x6b8d48fc,0x685a1405,0x0df0afd2,0xec6fc549'
      },
      {
        input: ['112,155,215,100,87,235,115,184,64,164,249,110,27,2,60,34,42,174,55,228,143,10,66,162,241,192,77,229,209,97,218,65,252,177,165,84,156,24,12,220,189,5,74,216,7,134,250,49,53,49,21,196,59,88,102,45,24,179,18,234,20,236,43,16'],
        expectedOutput: '0xfc55dbbf,0x511886d4,0x85efbc2a,0xad8adda0'
      },
      {
        input: ['157,209,100,57,233,112,21,166,117,96,127,124,230,121,174,27,171,195,223,230,27,69,19,52,248,38,30,12,18,73,29,176,26,129,233,4,242,255,170,103,95,41,228,69,163,146,97,78,85,64,52,113,134,72,165,126,110,195,139,128,12,168,48,39'],
        expectedOutput: '0x90acb7a5,0xfb7b0fdc,0xd10f587d,0xb405f1a6'
      },
      {
        input: ['41,26,43,27,25,213,131,120,255,103,189,162,249,30,240,78,95,36,191,229,108,100,99,218,39,238,91,52,150,139,91,192,165,134,219,190,91,94,54,90,197,244,252,190,18,236,13,113,17,204,86,125,49,186,88,88,168,179,140,63,62,231,255,228'],
        expectedOutput: '0x08a6cdee,0x4ca2726d,0xe9988efc,0x7f37d6e0'
      },
      {
        input: ['109,218,162,201,57,217,35,254,205,32,189,223,12,202,81,29,150,167,155,199,97,243,32,10,166,172,73,228,148,72,200,1,34,107,202,91,68,238,90,17,14,23,240,26,225,65,56,119,233,211,63,74,198,95,84,108,11,157,80,159,229,25,161,8'],
        expectedOutput: '0x155a513d,0x3ca0c683,0x0d12546d,0x844732ac'
      },
      {
        input: ['132,107,99,200,89,189,217,103,212,201,130,181,11,186,45,244,141,108,62,83,203,147,191,214,48,15,118,22,40,23,30,172,130,129,116,220,63,77,67,19,23,197,201,34,127,246,22,12,98,84,95,45,231,30,3,24,46,121,46,86,144,76,3,19'],
        expectedOutput: '0x16d12ca0,0xcbe9e40c,0xfc43c877,0x6671383c'
      },
      {
        input: ['205,119,239,12,197,50,32,220,248,233,254,119,223,20,132,65,104,227,110,80,2,113,104,48,235,150,134,123,226,137,142,175,1,125,188,198,176,220,162,168,197,160,31,164,180,163,229,28,135,83,108,137,196,212,185,175,106,63,43,76,201,185,252,202'],
        expectedOutput: '0xdc4d91c0,0x387ac0a3,0x971bccfb,0x742c93ff'
      },
      {
        input: ['55,184,144,231,148,50,143,89,210,174,253,134,82,226,162,217,53,15,98,249,227,27,169,78,90,212,154,35,141,150,237,196,78,125,171,226,175,58,59,129,233,56,7,59,26,170,20,79,185,118,73,156,145,242,234,235,198,133,15,83,27,252,24,106'],
        expectedOutput: '0x13a0c63f,0x333185ba,0xebabb4f0,0xa91c1227'
      },
      {
        input: ['122,195,76,41,254,136,171,231,192,178,34,219,92,54,42,21,172,115,178,61,101,156,40,43,33,55,127,61,52,151,167,174,90,243,215,88,123,130,63,60,53,97,23,145,151,65,167,67,181,89,128,26,245,169,70,23,224,197,84,20,92,251,194,182'],
        expectedOutput: '0xfdee2997,0xea640ffa,0x08c0d260,0xba4b5989'
      },
      {
        input: ['238,154,15,106,28,78,166,81,176,189,227,71,254,138,139,179,227,11,206,216,180,20,239,149,217,67,169,53,62,108,235,45,6,250,151,34,73,61,116,249,250,87,64,248,225,203,172,196,215,122,156,139,142,140,32,103,207,202,156,14,54,135,59,60'],
        expectedOutput: '0x77edbf6c,0x04e55cc8,0xc3f07c0f,0x16907790'
      },
      {
        input: ['130,210,94,203,15,210,196,9,41,4,1,10,208,173,206,167,39,107,50,181,247,83,28,198,29,184,212,83,64,15,143,194,225,237,141,240,192,81,249,233,85,251,244,37,168,194,204,208,45,255,133,36,82,162,235,111,90,191,194,154,207,81,92,176'],
        expectedOutput: '0x1cee1b82,0x21838f1b,0x299d26a9,0xaf508f3c'
      },
      {
        input: ['62,233,161,254,58,154,232,144,149,220,181,62,158,130,14,204,129,147,240,211,53,219,66,144,155,4,42,106,85,135,26,147,112,187,146,171,86,122,59,235,86,240,41,244,114,55,192,243,203,177,198,0,140,8,144,39,12,187,145,97,66,172,245,178'],
        expectedOutput: '0x30113509,0x8d3c2978,0xca7aed00,0x1082d2f1'
      },
      {
        input: ['103,135,93,189,1,152,169,87,137,210,75,251,10,12,239,213,189,181,213,73,190,102,113,202,33,2,44,99,174,33,21,22,168,115,211,169,11,124,0,148,79,75,144,89,87,127,46,20,52,3,94,242,105,207,189,138,209,233,237,128,10,3,150,178'],
        expectedOutput: '0xba5ee7c0,0x83eed310,0xf8995147,0xbee9ec34'
      },
      {
        input: ['118,105,91,129,230,91,22,53,166,166,142,254,37,188,18,89,191,112,76,41,63,9,179,17,242,161,145,252,164,39,174,26,144,9,155,118,100,177,171,10,87,57,8,124,245,27,214,181,139,34,222,203,43,145,220,29,50,109,25,214,148,199,240,36'],
        expectedOutput: '0xf54890d6,0xd39d597a,0x8c14faf1,0xcd60596b'
      },
      {
        input: ['208,140,155,52,61,70,62,149,128,71,17,117,98,231,42,237,9,8,184,52,154,148,81,204,1,106,163,149,49,147,186,1,31,85,53,93,155,116,242,27,187,3,145,29,235,187,10,244,196,195,41,94,87,122,42,89,229,205,238,22,97,168,24,128'],
        expectedOutput: '0x5e4da71b,0x9fb3e793,0x0e0afe28,0xedde1843'
      },
      {
        input: ['253,77,221,153,193,207,180,124,211,69,153,190,1,164,178,197,103,219,35,190,86,77,23,59,27,6,81,124,174,105,252,172,183,218,69,120,169,249,245,124,63,142,58,64,50,237,5,153,200,40,88,30,117,111,89,144,117,171,12,36,20,9,208,203'],
        expectedOutput: '0x186119c7,0x6ae077bd,0x1feb3bed,0x7729059a'
      },
      {
        input: ['227,21,68,140,14,57,9,77,199,67,141,250,48,146,147,249,186,235,23,48,91,113,192,208,28,205,244,48,214,196,252,185,217,64,69,232,121,78,53,64,146,195,58,194,85,206,187,16,185,211,64,20,68,0,229,96,205,217,144,163,158,140,92,119'],
        expectedOutput: '0x081de529,0x28eef632,0x50af3beb,0x768c6508'
      },
      {
        input: ['204,162,95,69,240,149,134,130,88,192,69,173,142,0,189,72,211,253,92,23,254,65,119,203,27,8,111,185,148,203,48,97,109,144,166,94,37,44,224,125,237,37,42,123,38,232,195,249,229,32,17,227,97,136,175,124,144,30,53,37,233,102,134,87'],
        expectedOutput: '0x74e3cc17,0x8bb70bac,0x3e24eda7,0xa142a9b6'
      },
      {
        input: ['246,44,181,27,89,149,152,70,187,194,193,225,170,133,218,144,165,235,115,6,116,34,131,4,64,184,41,42,30,175,129,20,220,54,47,53,203,199,123,134,138,60,103,52,193,66,196,102,45,56,109,161,90,240,166,155,168,207,197,199,127,70,219,91'],
        expectedOutput: '0x5cb8123d,0xd4463e40,0x91982c57,0x9a89e99b'
      },
      {
        input: ['124,11,144,71,210,11,206,92,71,53,145,9,119,85,111,165,141,220,70,232,204,236,131,117,188,72,60,59,142,23,150,10,34,38,81,245,49,31,81,120,85,226,129,204,56,241,113,197,205,184,173,154,164,48,15,96,120,75,155,6,98,49,16,133'],
        expectedOutput: '0x59775904,0x26fb5d76,0xcd1b804c,0x3d9c3764'
      },
      {
        input: ['87,98,122,136,129,203,1,214,174,130,163,230,115,20,171,65,204,89,219,113,137,234,209,2,53,109,8,151,158,25,28,246,123,150,126,252,98,127,211,16,2,118,246,117,138,161,182,87,250,145,200,132,123,153,134,176,6,142,72,165,167,100,155,34'],
        expectedOutput: '0x8dd6ddef,0x40b5875c,0x4a8a9b05,0x626758a7'
      },
      {
        input: ['251,25,31,93,153,242,109,155,104,99,16,242,4,199,73,255,88,17,131,212,171,9,132,177,151,204,86,63,49,241,97,44,11,128,137,164,114,246,63,218,89,79,205,93,22,22,92,111,40,223,67,211,232,199,132,128,148,219,191,197,204,32,241,215'],
        expectedOutput: '0xcebcc24d,0x2397399f,0x501450ae,0x712443cc'
      },
      {
        input: ['161,122,123,19,112,186,238,201,10,187,38,32,209,131,143,249,98,210,204,75,154,81,203,46,44,138,243,248,170,228,208,75,94,75,95,206,6,77,151,16,8,189,48,217,64,192,211,163,146,159,238,44,240,185,90,28,67,77,21,237,49,229,57,143'],
        expectedOutput: '0x5532369a,0x6b5a82de,0xd374fd36,0x37c53b10'
      },
      {
        input: ['48,152,93,54,229,244,70,237,178,119,198,242,55,153,149,201,57,131,246,41,60,80,70,127,158,91,109,207,64,166,95,112,62,188,167,35,177,237,16,99,100,214,85,155,112,235,101,169,110,91,210,171,171,24,42,73,115,151,25,179,61,120,36,123'],
        expectedOutput: '0x31f6118d,0x34b698c3,0x798285f5,0xa1bf8fa8'
      },
      {
        input: ['52,203,158,229,184,174,72,29,133,158,184,245,137,29,158,247,120,112,162,36,137,205,109,252,100,134,176,162,254,212,29,51,159,188,24,87,106,97,116,239,255,45,228,136,74,130,127,195,243,34,231,124,239,84,120,83,219,40,245,217,252,19,12,155'],
        expectedOutput: '0xcf8b6905,0xd4279fa1,0x82b59d06,0xe9846898'
      },
      {
        input: ['207,37,243,57,134,103,41,133,148,13,13,223,144,140,162,131,174,137,255,157,221,119,241,184,160,230,146,156,249,158,56,200,195,43,2,73,146,43,206,39,56,219,6,200,104,168,75,22,49,74,180,14,194,165,199,98,139,89,254,133,247,54,77,187'],
        expectedOutput: '0xae31f6ba,0x5e374457,0xcf6fc313,0xfe3a2d37'
      },
      {
        input: ['97,79,4,244,122,211,27,179,174,33,123,22,201,199,45,250,17,225,8,211,134,207,53,17,40,52,150,32,106,228,219,204,51,223,192,174,178,219,97,97,252,220,119,197,163,164,191,181,133,199,136,11,151,190,29,191,242,179,223,92,151,186,40,203'],
        expectedOutput: '0x89a379da,0xc5b9ca13,0xcb57a428,0x936c3338'
      },
      {
        input: ['154,232,121,76,195,218,173,191,182,37,132,90,201,67,15,79,11,151,90,162,85,119,97,71,43,65,164,194,251,204,141,149,181,6,226,120,224,143,56,151,180,188,241,126,0,0,205,11,151,39,173,237,159,14,52,202,79,216,140,75,165,26,224,90'],
        expectedOutput: '0xda3877b8,0xd097ffb8,0xeee004de,0xa2d52f58'
      },
      {
        input: ['32,194,210,1,82,10,152,6,199,137,132,199,137,81,210,32,121,127,13,24,141,66,226,221,26,110,40,191,136,8,25,169,203,236,170,29,246,66,35,189,203,168,132,84,249,86,116,114,213,130,138,99,196,108,64,222,219,104,158,99,112,183,12,59'],
        expectedOutput: '0x0bd8488e,0x1f92c0b9,0xd0720468,0x65e8a9ad'
      },
      {
        input: ['163,182,88,154,248,124,87,195,36,220,23,29,50,140,144,8,14,26,107,210,135,171,176,98,19,78,197,131,6,210,191,169,136,23,67,129,147,155,68,183,119,92,213,169,232,101,177,246,127,28,200,6,199,120,104,218,199,46,94,205,0,29,118,136'],
        expectedOutput: '0x3819c32e,0xebe4536d,0x743276c9,0x8ff08dd9'
      },
      {
        input: ['52,186,9,200,85,78,127,204,170,84,117,146,185,39,136,57,67,80,63,11,200,168,229,143,214,67,92,214,96,211,94,149,141,104,93,226,182,220,174,96,49,35,242,234,74,122,35,142,202,99,153,146,11,126,34,225,194,126,183,34,81,21,183,222'],
        expectedOutput: '0x5e0b9d5c,0x539ac4c2,0x27d3d8b0,0xe39a67e1'
      },
      {
        input: ['125,20,192,51,241,110,147,34,146,133,12,220,255,48,106,201,147,3,92,158,130,126,127,68,252,54,102,78,75,30,44,201,50,237,252,35,91,144,69,237,21,82,202,21,130,52,222,21,56,58,179,186,184,50,254,181,104,100,3,179,130,47,124,181'],
        expectedOutput: '0xbb17062c,0xdef53f5f,0x3d9bf7ad,0x72674976'
      },
      {
        input: ['28,121,216,120,9,30,101,30,112,47,51,242,100,18,7,156,76,186,86,5,236,84,186,84,184,189,7,59,236,132,240,9,253,200,129,6,230,230,36,86,22,88,72,122,106,79,22,182,9,108,187,245,192,117,73,120,50,81,179,31,213,163,40,210'],
        expectedOutput: '0xec1a385c,0xfa500d80,0xbcc07ffd,0x2fa21578'
      },
      {
        input: ['108,169,216,82,143,252,169,165,84,241,31,190,65,53,117,74,161,48,64,97,166,137,218,216,218,141,247,175,49,31,129,157,200,89,239,88,86,152,253,170,138,29,105,203,82,222,21,244,14,85,85,180,223,47,141,185,189,132,105,238,164,234,139,108'],
        expectedOutput: '0x8661c579,0xbcfef0cb,0x63c126ae,0x4da5a2c3'
      },
      {
        input: ['68,122,196,154,19,194,68,157,223,173,104,49,139,125,37,154,211,123,78,178,170,219,107,103,96,212,85,4,191,224,112,3,91,53,157,110,247,225,11,214,143,115,7,26,240,45,180,195,168,3,117,82,222,225,186,62,181,15,66,116,240,179,119,75'],
        expectedOutput: '0x61c79659,0x28052d31,0xf6a2dd6f,0xad76bf87'
      },
      {
        input: ['232,20,185,223,246,196,181,133,55,188,159,39,233,84,235,145,87,96,228,53,65,158,116,247,173,182,107,157,105,227,232,81,247,161,48,237,101,229,114,156,162,18,196,139,102,175,29,189,15,1,242,81,159,102,72,76,29,179,234,134,150,210,216,142'],
        expectedOutput: '0x1c2ee309,0x55244b5a,0x2dbced39,0x3a1a35b1'
      },
      {
        input: ['116,8,123,217,238,238,118,144,0,58,27,102,233,56,35,248,57,21,73,216,124,145,37,153,69,15,31,219,225,247,105,85,0,229,47,238,211,165,126,211,223,153,57,200,210,92,192,11,113,10,228,237,155,9,134,224,24,166,188,249,157,37,79,157'],
        expectedOutput: '0xc5260eac,0x984a37e1,0x20ec2791,0x67e3e2d7'
      },
      {
        input: ['10,126,139,221,35,9,176,2,163,233,202,117,69,138,128,183,148,100,164,48,109,43,16,133,209,204,127,110,242,206,12,252,76,151,218,111,161,138,113,68,116,59,185,185,197,57,112,90,158,21,138,11,64,154,145,17,103,16,127,89,222,139,85,42'],
        expectedOutput: '0x7017b0bb,0xad88a68d,0xd751c31c,0x67f3daed'
      },
      {
        input: ['35,47,153,196,186,10,8,46,69,193,231,10,250,88,100,152,109,238,164,173,137,53,190,240,69,61,73,35,201,158,77,236,206,230,176,136,240,184,182,53,121,157,63,115,245,164,12,98,146,176,15,27,229,205,11,42,11,84,77,212,243,154,192,193'],
        expectedOutput: '0x2d880aaa,0x58f055ec,0xe30c8e99,0xa3021d52'
      },
      {
        input: ['128,112,73,112,40,255,165,161,156,228,20,146,136,32,244,27,208,4,54,181,209,66,223,220,150,44,176,137,198,112,74,70,224,147,182,8,146,91,169,47,64,190,193,200,222,181,227,175,185,26,100,139,92,68,103,242,112,24,124,55,136,198,125,105'],
        expectedOutput: '0x6d38fe35,0x59218d8f,0x59a1fe11,0x9702ea8a'
      },
      {
        input: ['90,52,113,236,143,27,27,207,217,220,152,183,146,123,102,75,149,203,214,241,15,62,228,127,86,96,182,222,38,52,71,128,104,185,109,247,212,136,199,173,101,95,100,247,218,203,66,112,150,25,97,165,87,69,36,173,165,219,139,204,15,211,76,119'],
        expectedOutput: '0xf8e1bb65,0xf156cf2c,0x59055ac1,0xc3359a70'
      },
      {
        input: ['140,185,110,96,66,53,13,167,148,113,158,111,60,224,223,210,249,64,119,80,134,156,253,43,119,137,247,134,92,68,253,232,253,107,72,63,161,85,230,53,198,132,164,3,101,131,213,94,196,77,175,74,233,172,117,96,53,109,230,145,177,227,121,174'],
        expectedOutput: '0x68c4cc77,0xf89ecac6,0x27eaaeb3,0x876133c9'
      },
      {
        input: ['78,193,238,239,22,212,37,221,89,201,224,190,77,181,28,17,2,203,91,235,120,208,75,173,61,49,63,238,20,184,157,99,122,139,82,144,95,119,109,184,65,77,118,142,3,147,159,5,94,250,241,214,202,60,132,8,110,195,246,130,123,147,229,245'],
        expectedOutput: '0x9b799ad7,0xd8af0716,0x0f07bb75,0x23cc9cd1'
      },
      {
        input: ['30,56,134,126,175,243,54,240,65,173,126,68,64,29,73,158,23,58,117,226,119,249,234,229,188,224,103,55,116,77,45,146,133,179,16,52,166,71,37,231,244,163,43,52,193,117,210,216,175,71,186,38,64,164,11,252,133,115,52,249,192,97,139,69'],
        expectedOutput: '0x120d4744,0xaf605244,0x7cf3592f,0x5e9d6c93'
      },
      {
        input: ['20,156,121,186,227,158,162,215,66,205,11,3,66,221,219,242,37,150,24,101,58,36,98,191,151,150,184,87,247,68,156,11,224,21,197,195,180,103,154,246,53,165,249,119,130,212,105,167,106,130,13,165,166,111,100,61,5,29,148,252,97,48,7,65'],
        expectedOutput: '0x555a24e6,0xcb039b23,0x4498a8fd,0x1237d3b9'
      },
      {
        input: ['69,204,4,249,52,158,239,105,67,232,224,197,189,74,109,39,204,122,204,114,233,49,175,238,78,67,234,175,115,241,240,184,189,244,178,241,146,161,90,213,138,59,154,71,133,7,110,81,129,59,195,106,108,114,88,186,181,66,105,40,51,89,224,241'],
        expectedOutput: '0xe7e47348,0xe49fd89b,0x79460116,0x4d0e671c'
      },
      {
        input: ['77,146,226,223,52,61,180,190,120,78,5,253,86,115,78,215,174,17,66,26,131,154,212,56,221,61,96,16,150,64,1,227,211,228,194,7,33,118,197,153,197,202,150,27,61,228,242,236,245,52,6,120,207,219,176,172,24,16,188,175,80,190,146,35'],
        expectedOutput: '0x616d4043,0x57031206,0x16998457,0xa92e982c'
      },
      {
        input: ['162,85,42,195,203,239,92,144,185,242,171,247,214,158,227,203,210,233,67,161,196,243,77,221,3,10,140,83,200,30,119,106,115,161,45,63,145,137,207,74,123,123,65,81,25,36,28,235,14,95,141,210,82,218,175,85,228,59,168,172,90,31,22,205'],
        expectedOutput: '0x6ccc34bf,0x68f4cbf6,0xd1468eb2,0xf1429ef8'
      },
      {
        input: ['193,67,12,82,204,220,156,71,87,222,152,112,2,180,91,16,19,232,227,101,195,146,186,167,206,99,84,40,130,106,245,67,174,2,149,122,222,50,194,53,16,90,165,18,15,0,35,34,233,6,136,172,152,66,83,102,165,167,142,40,18,132,107,192'],
        expectedOutput: '0x89a13b30,0xef35a894,0xc8ee23b3,0xd6e6a08f'
      },
      {
        input: ['134,1,58,100,51,252,153,67,87,62,85,102,62,120,136,39,126,16,211,23,83,39,125,248,206,12,32,224,144,140,160,22,141,219,122,192,215,19,3,46,81,88,148,143,209,29,183,79,45,138,102,128,177,228,121,128,240,153,96,128,37,1,150,178'],
        expectedOutput: '0x3aba0318,0x2f64f6cd,0xa19532b0,0x0f7853ce'
      },
      {
        input: ['220,16,114,179,35,117,226,116,206,118,3,159,147,186,238,193,69,85,65,246,57,186,118,41,84,215,169,121,216,63,44,180,79,158,103,114,20,73,230,226,192,233,129,83,164,111,20,233,196,86,223,253,16,86,38,100,45,207,222,5,14,10,185,93'],
        expectedOutput: '0xf93f6ed7,0x91a2307a,0xf1589009,0xe97b1c32'
      },
      {
        input: ['168,32,207,188,106,181,158,42,159,31,125,67,143,146,44,83,232,11,81,248,97,119,93,142,71,59,147,85,69,76,179,237,109,130,170,215,56,72,1,215,104,126,26,247,16,70,74,248,81,155,241,179,19,78,65,90,137,213,175,206,33,98,187,142'],
        expectedOutput: '0x5aa97496,0x2ecca2c0,0xee1ca2b8,0x1dc37886'
      },
      {
        input: ['229,101,101,29,174,102,244,22,229,14,13,245,84,87,238,165,243,223,88,6,45,154,96,182,111,15,132,144,114,63,31,87,165,132,116,83,235,104,105,208,118,118,197,202,205,179,111,192,146,200,198,191,98,38,117,209,54,249,97,168,57,128,255,222'],
        expectedOutput: '0x87498c87,0x0637036d,0x29edf8e2,0xfe849546'
      },
      {
        input: ['5,115,49,240,219,154,192,81,16,133,27,221,57,138,158,203,82,100,139,180,139,0,133,193,250,231,105,51,103,104,17,108,219,66,92,182,220,28,7,236,162,34,201,219,172,103,166,255,204,49,179,87,50,57,24,44,32,129,95,135,233,112,244,196'],
        expectedOutput: '0xf7684c6e,0xe127176c,0xe8395c76,0x0cfa86f6'
      },
      {
        input: ['178,80,122,142,109,129,122,15,163,67,234,79,171,144,78,119,194,2,206,244,59,230,32,91,103,127,226,80,239,214,20,161,39,142,47,148,15,169,163,178,236,141,1,151,29,80,14,223,82,220,211,141,194,243,232,41,114,202,121,97,161,141,2,200'],
        expectedOutput: '0x7a27500d,0x2291dcab,0x1a7995df,0xabd7dcfb'
      },
      {
        input: ['27,49,92,42,218,255,220,199,140,222,94,169,46,109,137,128,73,92,13,12,80,245,53,194,191,175,36,96,60,38,40,88,88,132,130,50,131,95,249,15,61,88,185,107,197,66,235,14,158,248,26,238,237,80,177,172,255,213,13,59,251,53,147,83'],
        expectedOutput: '0x47bca09e,0xc82fcda7,0xbed4b509,0x1a8ba755'
      },
      {
        input: ['186,22,134,61,117,127,77,178,215,6,29,156,72,8,171,230,0,197,213,237,21,134,153,20,91,166,80,86,220,227,170,150,249,48,211,110,175,32,32,135,38,61,35,110,69,206,85,69,148,42,50,169,176,204,190,11,114,14,97,78,241,11,228,235'],
        expectedOutput: '0x7a5551a2,0x86ce7e65,0x70af4683,0x908e6794'
      },
      {
        input: ['59,184,89,235,216,122,114,255,183,149,109,253,100,194,66,248,236,117,161,156,65,95,167,179,109,9,2,95,20,230,74,80,158,163,59,119,29,173,118,213,66,227,210,166,166,20,158,146,137,64,47,202,159,214,126,13,223,128,108,244,102,182,68,5'],
        expectedOutput: '0x4d95e2b3,0xd6d8e753,0x7fd28ea9,0xb81620c0'
      },
      {
        input: ['89,127,124,119,44,242,76,110,213,30,21,123,50,179,14,188,243,61,134,147,19,4,160,243,132,12,231,235,194,43,240,27,170,108,146,214,94,222,68,51,252,89,175,47,13,189,235,0,250,113,147,13,118,51,0,250,63,231,229,1,18,213,29,188'],
        expectedOutput: '0xfe4da06d,0x949401a9,0xb8d920d0,0x9d89f28d'
      },
      {
        input: ['65,175,146,159,142,215,211,138,48,130,185,61,63,164,62,57,22,209,70,140,5,71,134,68,46,108,70,65,65,99,253,131,18,144,34,160,103,245,43,151,119,228,213,182,137,19,239,159,228,54,43,233,125,177,46,171,29,116,236,95,215,234,226,233'],
        expectedOutput: '0x92708e77,0x94fded39,0x98c09095,0x9b983b49'
      },
      {
        input: ['122,4,138,225,250,181,120,113,153,77,40,34,96,23,193,69,77,236,46,202,158,92,118,187,208,98,26,167,76,252,145,198,1,27,167,251,208,32,108,105,109,148,140,206,172,77,19,249,58,65,196,216,158,58,147,110,156,174,22,233,170,167,175,171'],
        expectedOutput: '0xa9ae9ad9,0xadbf3a85,0xfca42ee6,0x0822336f'
      },
      {
        input: ['194,87,166,146,119,19,251,228,167,135,178,83,213,197,77,15,7,17,231,165,75,122,19,231,40,41,208,211,208,128,126,146,215,37,36,78,56,32,50,223,167,229,51,124,170,128,139,177,145,114,86,220,237,106,195,21,147,148,232,100,20,103,246,235'],
        expectedOutput: '0x9beb3d8c,0xf67d4529,0xbfe13a9f,0x96d5e78a'
      },
      {
        input: ['140,27,57,196,59,107,163,226,80,214,95,251,86,234,172,231,93,3,195,74,109,135,95,0,27,72,100,47,175,91,26,59,118,83,255,177,190,162,147,15,121,242,10,207,221,182,183,58,185,122,132,38,1,227,39,28,43,139,75,218,230,101,21,92'],
        expectedOutput: '0xaff5d42d,0x769ed610,0xd5b1ff2c,0xc020dd5b'
      },
      {
        input: ['184,20,13,119,183,161,134,48,147,144,255,112,70,182,170,0,49,46,38,50,18,77,79,61,217,154,24,191,0,45,28,184,66,41,47,249,202,181,41,94,69,40,206,140,223,121,140,16,167,178,66,185,0,145,247,217,44,15,152,44,60,180,228,126'],
        expectedOutput: '0x780acff9,0xe0184f87,0xe106de97,0x7d0af67f'
      },
      {
        input: ['222,20,119,168,201,160,6,15,201,213,155,168,78,39,184,245,217,250,175,217,140,166,178,184,181,75,228,241,255,200,112,221,220,231,134,166,136,140,181,81,97,80,249,175,119,177,165,80,171,84,42,55,250,220,239,175,39,211,160,39,156,16,4,120'],
        expectedOutput: '0x9b63ca3e,0x581e6abb,0xaec17106,0x7e1cc282'
      },
      {
        input: ['248,138,30,128,23,211,209,120,35,202,40,154,123,205,235,38,33,21,94,27,241,77,202,25,33,106,64,189,123,68,53,115,207,84,243,230,39,196,94,75,142,134,229,9,83,208,47,116,229,141,143,215,219,89,240,252,196,48,185,63,116,238,178,67'],
        expectedOutput: '0x46fbf637,0x555dcce6,0x4bf3f6f0,0xa3483cbd'
      },
      {
        input: ['66,165,41,106,105,136,181,247,14,154,0,98,107,47,214,80,189,102,39,152,191,23,148,131,71,77,194,188,59,116,255,126,25,41,232,130,177,157,121,191,55,121,33,162,169,248,243,102,94,26,254,29,50,146,161,121,223,99,53,26,216,53,152,241'],
        expectedOutput: '0x09d49564,0x480209b7,0x82ed2687,0x2ce63491'
      },
      {
        input: ['94,128,116,15,29,237,206,85,103,240,247,16,232,234,118,70,5,116,99,55,6,4,176,229,104,230,255,64,27,152,49,121,24,165,136,54,147,86,139,250,70,130,10,46,109,128,116,114,244,216,169,250,220,89,223,68,63,222,132,90,118,182,211,143'],
        expectedOutput: '0x87a3ef55,0xc8ee4aad,0x002ef619,0x20587242'
      },
      {
        input: ['91,91,197,238,178,80,232,248,210,242,39,63,114,155,177,102,115,90,96,80,180,63,148,243,30,25,78,148,207,33,35,42,125,232,25,47,56,1,39,11,244,78,74,102,234,252,205,93,86,45,173,10,109,66,254,139,91,76,31,42,109,67,84,234'],
        expectedOutput: '0x87579e2c,0x2f7956a4,0xb9280be0,0x9dfb36f9'
      },
      {
        input: ['43,109,25,100,111,65,111,99,143,185,201,121,181,150,215,12,196,132,22,49,198,20,188,33,96,219,75,206,30,160,184,74,13,210,174,124,19,29,223,162,214,169,28,140,63,243,152,3,119,174,52,62,195,240,95,35,204,171,241,234,75,170,52,88'],
        expectedOutput: '0x67a4d3d0,0x348a24da,0xbcd537e2,0x0bba169a'
      },
      {
        input: ['124,226,213,143,255,180,49,214,93,77,98,157,64,250,160,184,168,213,246,107,197,85,143,145,0,128,124,75,42,176,164,166,147,121,53,146,45,103,104,139,180,202,40,245,196,200,173,109,157,163,216,99,248,103,244,249,232,112,68,18,33,232,185,180'],
        expectedOutput: '0xb3b3cde4,0xda615d38,0x48144970,0xbd28477d'
      },
      {
        input: ['97,238,70,143,85,175,26,10,121,66,255,62,10,172,171,168,79,131,11,71,235,255,64,211,112,133,229,145,109,158,69,207,141,139,94,226,58,120,236,180,186,235,242,196,151,157,108,230,32,119,46,11,119,110,222,231,243,196,120,97,98,189,48,239'],
        expectedOutput: '0xdf09ad58,0xef8b3ac8,0xefdb9b24,0x1729bab2'
      },
      {
        input: ['72,142,210,131,6,190,55,192,170,41,132,65,198,241,40,230,104,86,242,223,196,208,198,184,148,62,25,247,251,73,230,68,215,184,199,221,119,254,157,33,39,33,98,237,18,138,211,123,224,197,90,165,150,33,93,42,95,118,33,91,191,8,159,150'],
        expectedOutput: '0x337b9869,0x55b1fea7,0x66b9dc2a,0x23b9e6d9'
      },
      {
        input: ['192,102,115,55,100,16,88,139,49,187,120,68,69,75,191,38,17,25,203,167,58,40,209,154,158,243,245,93,251,148,243,187,250,102,243,94,118,75,233,167,6,97,235,76,172,170,114,189,196,61,100,254,101,54,152,3,41,141,96,36,33,83,223,27'],
        expectedOutput: '0x56be727b,0x7d1d5cb0,0xb2a27bfc,0x955b4716'
      },
      {
        input: ['185,210,121,47,30,98,214,36,195,194,112,112,108,226,45,48,31,146,47,132,200,199,135,241,85,231,21,118,58,244,146,243,199,11,34,229,110,249,9,49,187,122,161,39,92,207,88,124,97,135,0,41,78,136,26,163,111,47,26,170,35,172,157,234'],
        expectedOutput: '0xc2269cc2,0xb0529826,0x9a7b1d17,0xdba24f3a'
      },
      {
        input: ['183,192,207,37,185,217,87,116,83,248,155,175,199,243,43,40,122,44,81,201,180,107,108,35,154,134,205,190,50,107,168,234,43,120,15,228,81,102,88,164,95,243,83,38,231,127,79,97,171,160,42,95,12,151,130,166,29,80,100,80,187,13,58,230'],
        expectedOutput: '0xbb7ecb03,0x528ff1af,0x99bf281a,0x59afb617'
      },
      {
        input: ['133,73,202,214,176,34,122,15,21,205,53,252,76,132,94,247,37,136,86,49,31,217,215,61,41,60,141,228,73,199,202,206,16,148,164,192,182,30,207,203,235,5,200,56,137,38,47,174,174,134,223,206,95,183,11,136,243,152,108,60,95,54,10,111'],
        expectedOutput: '0x42e6cba0,0x289ecce7,0x0fa7313f,0x6c47001c'
      },
      {
        input: ['202,174,48,128,204,255,75,183,4,19,239,142,57,31,60,232,165,28,182,4,211,193,140,198,89,248,2,184,46,12,39,248,186,87,120,134,87,195,61,91,215,45,233,16,76,38,248,241,66,174,245,21,111,129,219,200,121,221,128,167,233,168,159,163'],
        expectedOutput: '0x95331ce8,0x24c33e59,0xb3331c08,0xae7f8bfb'
      },
      {
        input: ['255,23,41,86,218,102,178,177,147,155,194,223,193,186,208,3,105,197,24,216,70,243,161,191,208,33,102,185,201,5,92,201,28,133,31,247,236,209,168,127,109,106,95,46,37,47,50,142,245,74,102,59,62,7,251,14,41,97,200,242,103,36,187,131'],
        expectedOutput: '0x4665b91a,0xf726288f,0xfb72c779,0xe61060ff'
      },
      {
        input: ['170,219,122,150,172,35,21,25,141,116,72,178,164,122,64,153,196,167,212,2,174,207,17,215,49,217,202,152,253,133,27,167,96,150,61,13,185,83,38,70,199,110,249,107,232,57,4,173,224,217,175,143,168,192,102,217,153,48,113,151,182,141,62,22'],
        expectedOutput: '0x32ab878a,0x8f3b4ca5,0xd4e4fd53,0xdb74b723'
      },
      {
        input: ['35,124,35,220,207,74,34,150,184,27,2,161,85,6,78,53,223,253,196,136,190,43,97,87,91,211,238,17,96,45,40,131,169,75,95,120,149,129,14,78,157,16,239,242,23,61,39,246,58,236,126,248,23,224,80,114,179,62,132,19,107,172,150,20'],
        expectedOutput: '0x689d4049,0x51822d9f,0x85a80635,0x2d2bf51f'
      },
      {
        input: ['247,245,140,141,118,155,219,19,171,202,5,194,7,45,185,65,25,55,58,48,23,138,162,202,200,38,221,52,210,115,72,202,104,213,87,223,112,50,242,27,252,248,222,3,37,151,68,62,206,126,110,230,8,16,176,209,55,142,5,9,1,77,211,106'],
        expectedOutput: '0x017cfbdd,0xde8555be,0x92095f42,0x66483750'
      },
      {
        input: ['34,42,73,146,92,59,174,88,51,140,91,88,35,160,150,241,30,4,215,39,21,136,248,76,22,253,85,23,74,41,129,109,83,202,255,176,6,173,8,57,57,100,146,92,4,40,78,34,45,37,73,66,173,65,142,195,62,227,219,137,12,92,246,96'],
        expectedOutput: '0xb70fe0f2,0x236489d8,0xed5464a7,0x82b4c238'
      },
      {
        input: ['39,245,16,45,163,24,102,220,124,248,57,128,33,135,163,78,172,236,144,90,46,30,29,108,1,248,245,14,85,235,110,124,225,126,169,132,150,15,96,19,8,153,147,41,32,54,119,205,35,7,39,81,37,68,189,38,61,179,52,146,158,162,14,127'],
        expectedOutput: '0xb9124cd2,0x26eda651,0xba562f28,0x67900512'
      },
      {
        input: ['32,183,3,183,198,100,202,206,253,93,247,30,148,110,235,183,117,18,8,154,86,197,193,147,120,245,37,23,152,51,150,184,234,154,111,177,254,57,127,251,151,119,25,43,229,4,226,91,22,234,245,109,175,182,0,40,172,38,63,68,89,213,252,68'],
        expectedOutput: '0x9cbb2f79,0xc2737a22,0x26265f40,0xb42876db'
      },
      {
        input: ['111,108,245,109,165,116,105,60,235,130,103,209,135,73,44,157,51,33,10,227,216,11,11,132,49,74,200,138,31,196,206,143,48,195,252,214,56,101,18,35,232,122,244,111,195,32,12,247,66,23,218,26,34,229,158,83,47,102,221,78,42,172,221,91'],
        expectedOutput: '0x62484b75,0xa5c8b07a,0x0705ffc6,0x7aae3666'
      },
      {
        input: ['111,218,49,167,63,67,203,39,189,191,150,129,224,163,120,34,186,82,60,220,55,218,47,102,64,12,180,106,184,146,197,40,108,246,207,171,58,154,211,247,90,105,120,58,12,240,92,198,66,152,162,121,114,209,223,178,222,148,28,150,38,226,190,146'],
        expectedOutput: '0x6fa22760,0x0f7f5087,0x5d5eff9e,0x3572a058'
      },
      {
        input: ['216,142,61,18,40,16,10,130,122,130,188,134,115,24,77,181,176,239,47,34,193,14,212,159,162,241,53,200,211,244,90,171,130,152,190,170,168,200,45,34,74,233,169,189,2,246,115,178,229,162,213,166,176,169,69,83,154,123,27,109,111,118,25,241'],
        expectedOutput: '0x16bb8a1c,0x883a8b54,0x4a665606,0x1fb007a2'
      },
      {
        input: ['14,215,155,182,159,200,217,233,178,130,167,180,120,26,102,93,188,59,4,108,229,73,191,127,196,219,237,51,81,6,36,95,221,192,21,124,136,238,101,58,112,12,238,232,38,85,70,226,144,74,79,117,147,14,245,88,233,226,139,58,232,176,153,197'],
        expectedOutput: '0x5d0b2f43,0x1b087346,0x74d79be2,0xa9920867'
      },
      {
        input: ['112,175,65,248,157,166,51,14,179,33,246,217,118,60,188,7,134,11,124,26,25,113,114,3,83,253,61,59,173,215,0,29,134,65,22,35,232,73,49,155,106,40,116,225,100,48,232,235,59,100,5,85,214,119,88,41,116,149,101,34,108,101,63,242'],
        expectedOutput: '0x2d67ca3d,0xc2655997,0x397c2257,0x9ca50956'
      },
      {
        input: ['167,85,22,143,158,71,42,9,111,158,234,212,207,210,191,10,54,196,95,12,59,183,54,175,77,155,209,185,0,17,172,167,102,194,54,5,9,96,14,121,255,248,77,206,202,12,216,0,208,56,13,11,239,67,186,60,222,140,246,222,157,162,134,3'],
        expectedOutput: '0x4d216999,0x1e3d6397,0xc195d40b,0xdddd5339'
      },
      {
        input: ['100,188,8,109,29,22,230,28,14,51,234,216,63,194,217,15,250,230,26,234,41,213,38,7,97,28,229,254,190,107,1,34,40,10,144,69,32,118,97,47,170,75,7,233,13,224,249,8,198,19,242,239,232,24,246,73,53,220,71,243,71,73,22,111'],
        expectedOutput: '0x280039be,0x58a6a92d,0xfea33533,0xeacbb746'
      },
      {
        input: ['83,166,180,115,28,21,162,198,96,170,176,110,138,169,118,81,188,104,64,165,128,55,238,181,19,54,169,90,127,191,202,210,101,126,69,129,148,232,72,244,146,248,98,28,161,216,109,93,64,174,2,193,229,241,118,248,39,31,82,166,222,28,120,67'],
        expectedOutput: '0x23c24734,0x956ad383,0x8206cc9f,0x00a9cbc2'
      },
      {
        input: ['155,189,197,47,165,13,35,55,5,134,84,166,94,193,3,159,111,6,96,84,247,214,76,30,246,159,196,212,187,60,24,86,249,221,133,159,234,169,214,239,47,42,149,141,236,152,44,91,158,140,176,149,99,252,179,89,155,119,45,87,179,69,173,173'],
        expectedOutput: '0x0d50a008,0xcea7381a,0x3e93e5c1,0xd7444369'
      },
      {
        input: ['34,51,76,12,220,34,251,11,77,144,152,57,41,197,148,199,81,68,93,180,65,16,13,220,136,59,51,59,128,225,232,163,20,52,175,240,87,171,251,164,59,147,221,100,88,113,44,170,182,137,94,247,153,108,211,33,167,7,93,39,232,69,202,252'],
        expectedOutput: '0xbb6056f8,0x04f8a8f9,0xde35027e,0xd21d089b'
      },
      {
        input: ['122,122,236,209,37,231,117,96,122,82,197,211,195,241,125,121,122,219,112,19,71,68,53,238,75,146,22,51,215,224,47,81,90,27,34,127,2,151,224,124,233,165,79,173,150,204,38,16,168,151,35,239,219,88,222,38,234,244,89,194,212,136,19,47'],
        expectedOutput: '0x8c4b55e0,0x2fd7911e,0x77c1e545,0xdb4a33eb'
      },
      {
        input: ['163,54,174,165,205,142,33,183,51,113,100,201,61,138,217,229,33,253,213,252,85,179,34,64,167,123,2,123,3,21,170,166,75,89,75,25,231,109,208,27,222,52,228,27,190,190,1,224,187,214,220,16,137,255,80,48,122,82,171,126,104,86,36,179'],
        expectedOutput: '0xf4569b05,0x45247c6f,0xadedf328,0x6af7289a'
      },
      {
        input: ['175,112,204,150,221,156,177,187,208,150,214,143,84,215,111,15,173,75,31,54,74,112,102,197,194,18,67,42,104,103,222,23,215,170,173,180,71,95,111,23,245,70,166,73,29,21,88,203,97,119,1,171,231,104,112,170,122,179,212,226,27,178,249,242'],
        expectedOutput: '0x912293ef,0x8f7a037a,0x1616bd2d,0xda84f0df'
      },
      {
        input: ['93,166,167,164,5,22,187,250,92,98,67,122,119,155,69,216,19,70,132,250,174,244,164,40,168,121,10,195,43,3,181,136,170,92,44,175,115,232,170,207,74,237,73,193,137,142,154,156,213,30,150,131,18,59,172,186,180,182,125,223,186,51,104,100'],
        expectedOutput: '0xf438953d,0x5448d280,0xe5045b00,0x04de99d6'
      },
      {
        input: ['143,148,19,2,124,189,210,198,171,27,136,52,170,34,208,127,64,102,2,82,161,174,13,85,101,138,53,31,189,157,131,77,49,150,79,174,84,33,116,255,61,252,51,231,30,3,102,94,105,104,177,11,23,190,96,124,72,149,155,6,50,30,83,100'],
        expectedOutput: '0x8b1fe055,0xbfca64c5,0xa80410d6,0xb5ed42fa'
      },
      {
        input: ['180,162,18,8,196,134,7,1,131,58,232,161,61,78,0,167,182,177,178,205,111,18,73,183,168,228,189,218,2,16,62,183,179,80,191,119,215,199,120,90,1,96,251,63,174,251,230,100,172,152,50,27,170,123,211,82,96,144,45,98,161,107,25,84'],
        expectedOutput: '0xd267d4a4,0x98aa5358,0x16212f94,0x2181a814'
      },
      {
        input: ['188,217,203,147,160,67,237,161,163,232,224,81,228,198,181,144,94,231,172,9,99,127,91,195,15,136,37,176,244,63,4,176,24,207,67,184,18,48,89,181,24,58,6,252,0,188,141,95,163,57,104,6,184,195,201,199,76,239,120,64,46,124,240,70'],
        expectedOutput: '0xd7b2992d,0xf22ea516,0xf503a2f2,0x26772d63'
      },
      {
        input: ['76,51,254,94,99,87,20,123,145,26,120,146,214,5,241,122,62,89,128,246,28,74,189,104,57,53,168,103,178,152,173,254,203,171,92,46,2,112,170,148,139,34,38,97,39,23,219,101,112,92,91,140,166,24,245,223,78,157,70,0,54,243,254,1'],
        expectedOutput: '0x020a8703,0x561561c1,0x2744f6df,0x303e4b44'
      },
      {
        input: ['158,90,48,160,203,218,52,86,252,90,183,35,113,147,136,225,239,227,110,149,251,99,116,73,0,186,73,54,173,71,56,75,162,104,235,109,66,32,195,62,122,122,97,236,13,233,205,252,204,59,145,199,158,5,17,159,191,90,213,108,162,13,183,68'],
        expectedOutput: '0xa2aca793,0x3346a98b,0xc6cb0a4c,0xc364339e'
      },
      {
        input: ['117,163,177,183,195,116,245,61,238,86,41,252,63,247,248,11,50,138,211,209,143,228,112,79,62,69,187,224,83,115,36,200,22,213,128,217,73,117,22,56,204,64,52,11,55,44,23,105,182,234,58,70,206,170,149,12,240,80,237,67,195,17,11,217'],
        expectedOutput: '0xb6b588fa,0xe20a16a8,0xe75aa0b2,0x6e78fe10'
      },
      {
        input: ['231,139,178,48,1,201,104,205,9,156,216,64,201,239,169,127,217,228,197,167,142,90,180,126,171,161,193,110,178,205,72,153,88,250,202,89,195,50,38,204,207,255,12,152,238,182,23,200,154,221,111,40,55,35,167,226,196,104,81,119,53,153,16,142'],
        expectedOutput: '0x19754e40,0xfca56980,0xac0da3ef,0xf727216f'
      },
      {
        input: ['147,218,231,87,13,14,35,220,13,48,116,251,230,139,195,128,104,51,168,160,86,79,130,27,184,211,146,237,108,162,123,0,125,99,87,138,113,122,102,126,170,218,121,144,101,61,16,206,112,185,110,198,8,240,225,192,196,115,174,48,22,41,48,147'],
        expectedOutput: '0xb2f8af49,0xccad21f8,0xa6e67f03,0x05ff9484'
      },
      {
        input: ['140,135,29,253,2,131,123,172,93,245,61,194,50,77,144,162,6,254,104,15,239,74,207,179,189,125,227,211,167,20,102,51,155,131,49,157,6,172,74,99,161,135,38,211,212,182,117,219,181,222,234,164,40,185,87,229,55,58,185,222,78,31,17,234'],
        expectedOutput: '0x3a23adf3,0x1fc1cfab,0x3508730f,0xfe8ae391'
      },
      {
        input: ['163,66,135,169,239,209,13,144,88,51,100,45,233,217,8,158,183,242,66,223,171,153,197,226,212,126,192,34,157,210,12,64,20,148,234,3,101,247,148,190,42,248,235,19,209,243,178,137,229,244,104,144,142,45,115,98,171,51,132,73,5,145,137,26'],
        expectedOutput: '0x6d489728,0x372c610c,0xd97230cf,0x666fc838'
      },
      {
        input: ['37,115,29,138,106,177,72,148,169,51,168,123,38,90,4,11,78,108,156,220,154,15,62,69,66,195,142,72,84,24,98,121,139,127,3,246,49,76,138,218,127,50,85,166,140,89,177,219,198,77,183,96,92,246,165,159,185,52,231,13,76,73,134,215'],
        expectedOutput: '0x0785490f,0x39f9e35c,0x5a1190c9,0xa2a8a902'
      },
      {
        input: ['200,137,205,249,213,88,212,85,138,41,251,23,131,172,242,73,250,169,169,86,159,78,245,88,130,220,101,206,37,235,166,238,117,115,231,74,203,187,159,86,229,154,109,104,71,95,177,65,8,90,151,168,168,141,0,43,105,102,249,143,81,159,125,198'],
        expectedOutput: '0x425961b9,0xd4e06fff,0xadfc3311,0x699bbd04'
      },
      {
        input: ['19,100,17,222,32,176,52,5,75,161,109,146,0,30,211,9,120,106,177,32,247,177,75,97,23,69,240,105,228,109,47,247,209,64,214,241,241,10,246,60,172,99,206,172,129,161,181,249,11,102,26,3,24,101,100,47,170,84,152,143,193,200,134,146'],
        expectedOutput: '0xed4240f7,0x08dddee7,0x6faba8a4,0x68c5a3ef'
      },
      {
        input: ['8,92,132,249,103,122,53,19,222,3,191,95,164,117,89,176,219,115,179,243,216,23,35,131,107,187,18,44,131,152,190,140,245,66,133,92,189,187,111,155,190,46,250,99,163,83,19,127,198,198,114,159,221,149,34,72,81,52,116,212,204,50,96,193'],
        expectedOutput: '0x3b8ed52c,0xa0f3dfa2,0x463252cf,0xdea8001a'
      },
      {
        input: ['117,230,29,50,161,140,205,95,187,199,194,94,27,213,221,225,155,80,128,120,229,162,192,54,214,52,11,163,103,107,100,220,81,130,14,242,14,219,82,201,162,20,40,189,234,5,159,133,85,31,254,59,194,190,113,152,243,124,59,90,232,160,54,57'],
        expectedOutput: '0x6219b7c3,0xc548e1c7,0xf0133454,0x557d70e6'
      },
      {
        input: ['34,68,44,48,31,126,250,193,146,34,127,124,39,30,2,125,61,0,184,255,190,41,152,177,166,211,11,142,115,65,199,149,133,243,198,164,113,192,102,4,226,229,128,9,3,130,134,64,130,62,64,65,104,216,242,14,171,254,156,31,63,99,180,197'],
        expectedOutput: '0xfaa41132,0x865d8872,0x1a309525,0x8d302615'
      },
      {
        input: ['87,122,105,200,58,207,204,28,180,77,38,183,207,172,248,82,235,56,147,83,16,133,97,187,131,253,218,195,96,143,136,183,9,241,128,68,193,76,96,117,153,134,45,105,51,37,187,30,93,78,113,109,211,210,40,87,207,3,26,47,146,162,231,155'],
        expectedOutput: '0xba7941bc,0x79e787ce,0x4d0fbdaf,0x1b5c1e11'
      },
      {
        input: ['147,103,223,84,179,64,202,77,198,247,182,249,28,113,23,121,191,136,230,146,90,14,233,41,17,3,89,163,165,64,63,57,167,30,141,90,94,87,167,37,78,93,30,106,206,54,227,141,190,201,32,25,216,9,66,233,13,155,141,178,219,204,235,130'],
        expectedOutput: '0xb7dff13f,0x2c074e13,0x79704ed8,0x2d617a18'
      },
      {
        input: ['234,121,221,73,208,132,110,31,226,140,137,176,194,109,62,129,54,94,154,14,103,220,248,116,120,133,39,83,81,18,214,59,139,179,132,92,55,242,123,25,127,4,202,65,113,8,194,168,102,92,182,205,57,174,66,177,51,105,4,132,123,218,192,7'],
        expectedOutput: '0xb5a08045,0x554ce197,0xf95af3e4,0x8759dee3'
      },
      {
        input: ['141,68,99,197,55,222,222,182,226,168,247,84,176,186,252,22,22,178,228,79,97,38,0,148,143,5,25,10,223,217,17,109,29,116,50,84,82,16,10,53,185,2,137,105,188,133,128,210,55,100,34,152,138,34,45,25,39,70,35,7,31,53,116,60'],
        expectedOutput: '0x9425f256,0xf92954e5,0x91efff78,0xffd30306'
      },
      {
        input: ['169,166,145,252,182,155,49,111,157,186,217,89,63,89,44,118,189,78,15,71,112,60,96,152,130,131,159,161,184,19,221,98,185,110,94,111,10,143,223,167,73,184,1,136,17,45,254,206,123,13,21,235,73,117,131,203,248,34,108,177,53,74,19,238'],
        expectedOutput: '0x3770f1a4,0x32558050,0x86188da7,0xd939593a'
      },
      {
        input: ['184,113,94,194,0,61,106,73,245,107,209,6,152,207,212,19,221,233,254,38,94,130,242,86,164,94,7,218,168,26,200,97,139,38,35,139,99,141,212,88,248,165,94,144,117,50,163,82,27,162,120,121,36,106,208,200,201,215,162,113,242,107,210,125'],
        expectedOutput: '0x08d03e76,0xd0174a40,0x3dd63baa,0x9483ad3a'
      },
      {
        input: ['145,246,9,245,131,221,77,124,131,172,12,248,222,176,74,250,82,194,115,118,45,67,62,246,27,225,103,13,76,58,138,221,48,147,210,179,113,32,47,244,204,60,236,170,236,54,164,62,248,24,180,37,91,242,27,118,211,131,131,31,189,14,253,237'],
        expectedOutput: '0x0ef59f80,0x5c549d61,0x3d6aae95,0x02dd9e73'
      },
      {
        input: ['161,207,160,18,239,208,6,187,12,242,102,248,40,10,54,33,34,234,70,126,220,98,244,176,229,120,207,162,134,204,143,39,156,47,58,139,255,64,71,11,51,173,3,91,183,57,124,218,35,195,88,0,37,76,176,10,196,127,172,74,76,59,114,232'],
        expectedOutput: '0x956dad60,0xc0e0521f,0xea511a72,0x45444b5f'
      },
      {
        input: ['106,172,115,106,236,186,117,31,103,121,123,31,178,247,249,214,186,81,214,223,157,134,233,98,5,149,172,81,208,30,57,59,202,173,165,183,103,26,214,207,147,81,238,70,73,231,28,3,56,242,227,213,120,204,55,125,98,228,207,50,2,8,109,205'],
        expectedOutput: '0x19a88459,0xaf85d88e,0xed60cbf0,0x0c4d7c99'
      },
      {
        input: ['181,18,132,29,45,90,236,192,172,218,6,245,193,34,248,249,20,219,206,140,168,6,10,10,234,217,60,236,225,170,185,151,188,61,180,233,152,160,170,68,122,176,57,59,211,49,52,231,13,2,116,181,8,126,191,242,87,251,223,56,165,152,207,98'],
        expectedOutput: '0xf67fbcbc,0x632f1b29,0xa27db83c,0xc4f50c1e'
      },
      {
        input: ['214,131,75,110,35,245,178,157,166,235,216,121,28,12,96,41,15,212,222,23,82,157,10,169,153,233,226,62,129,177,160,87,53,236,197,88,225,119,246,135,98,206,0,127,219,97,168,234,53,135,1,136,36,11,49,189,244,19,252,118,197,156,205,250'],
        expectedOutput: '0xfc8450dc,0x6c205e14,0x87a10634,0x3522ea2c'
      },
      {
        input: ['136,147,82,106,10,72,241,109,23,242,236,242,83,148,220,136,27,221,16,64,233,66,253,221,85,249,83,26,150,33,20,30,180,103,136,190,175,122,43,198,108,23,184,191,172,148,71,199,114,88,7,91,154,5,56,239,254,140,10,148,173,30,179,97'],
        expectedOutput: '0xe82952a9,0x6118c18a,0xb4421f7a,0xdbcc52a8'
      },
      {
        input: ['133,59,31,53,181,75,251,33,98,180,224,14,72,40,214,186,128,221,21,26,226,78,9,225,218,19,117,135,50,40,232,183,100,7,236,25,82,232,59,181,156,27,195,228,67,153,159,195,119,180,221,89,2,231,58,220,250,176,99,44,216,75,228,60'],
        expectedOutput: '0x03349d43,0xec87d95d,0x71573f16,0xb822d821'
      },
      {
        input: ['83,208,86,165,184,145,90,84,172,30,57,240,183,216,179,46,140,145,136,143,120,194,107,114,114,207,159,75,26,131,135,109,83,221,19,12,110,109,96,27,139,153,11,67,113,190,113,254,79,249,141,199,188,248,58,46,199,217,121,226,92,1,79,175'],
        expectedOutput: '0xe07aad3d,0xffd0e5b4,0x902d63e4,0x3e501a4d'
      },
      {
        input: ['222,98,187,77,208,28,104,91,181,115,158,39,49,16,37,129,9,178,72,197,170,130,244,114,91,109,84,183,110,163,103,77,6,34,154,214,62,2,49,244,117,208,27,166,224,64,39,233,242,112,175,156,242,163,14,78,16,98,5,127,6,108,204,12'],
        expectedOutput: '0xa3130741,0x653fd607,0x8d351151,0xf8bc770d'
      },
      {
        input: ['143,102,226,205,104,19,193,221,227,220,131,195,28,171,173,14,27,92,171,13,255,185,91,15,28,97,142,34,205,90,46,92,192,16,42,40,35,235,5,7,200,137,202,228,52,119,243,79,211,158,92,210,87,184,226,115,25,112,149,230,203,195,67,139'],
        expectedOutput: '0x808778b3,0xfd7ea8a7,0xa3f26e91,0xfbd45814'
      },
      {
        input: ['211,109,180,247,88,185,254,32,66,200,5,118,64,248,197,19,150,34,230,237,218,200,97,243,56,246,217,3,186,28,143,141,137,67,132,226,252,130,2,63,75,7,181,139,255,123,158,149,157,132,131,119,76,228,106,133,218,67,136,148,96,23,34,233'],
        expectedOutput: '0x599704e1,0x67905c02,0x6bb5f9be,0x6906789b'
      },
      {
        input: ['90,166,203,87,41,206,150,116,213,75,255,213,198,157,106,99,34,237,218,110,209,68,243,172,136,124,64,232,147,98,209,238,9,157,69,50,107,219,166,64,38,165,21,237,66,128,80,100,109,43,211,63,111,198,235,247,66,43,223,214,142,177,196,151'],
        expectedOutput: '0xcee3dc75,0x5e0b409f,0x1dbc2496,0x9cad05d5'
      },
      {
        input: ['78,9,201,185,228,111,249,10,20,15,247,86,143,72,187,252,115,142,59,226,84,38,218,151,82,185,109,224,106,49,119,184,58,64,113,30,175,107,40,195,122,32,25,9,104,212,5,219,98,65,189,183,103,151,78,185,81,187,153,187,236,16,116,38'],
        expectedOutput: '0x496b6ec3,0x363495a8,0x2e2b4765,0x8fd85a2c'
      },
      {
        input: ['80,229,68,255,80,108,194,202,140,220,211,244,176,217,207,19,26,141,202,129,36,24,59,117,211,212,49,191,229,165,229,53,138,41,53,219,149,247,165,34,211,121,22,132,82,230,151,108,115,97,237,151,121,40,13,76,253,62,11,226,227,240,23,109'],
        expectedOutput: '0x8a284d8e,0xa8f86f07,0x277d4c4b,0x024e1c54'
      },
      {
        input: ['25,76,72,174,68,238,208,23,103,231,155,185,205,50,37,64,147,18,215,12,59,228,88,56,34,99,26,5,83,49,115,108,126,187,27,194,169,235,217,16,210,117,201,159,167,238,223,59,1,183,71,60,155,160,116,190,3,142,195,87,191,54,195,61'],
        expectedOutput: '0x9aa6222c,0xc00ce268,0x9efce36f,0x21b6aea0'
      },
      {
        input: ['242,222,255,155,202,217,172,156,78,117,60,245,100,27,48,101,210,120,161,110,24,21,44,27,163,239,114,98,38,54,160,24,20,159,179,222,120,95,123,198,213,183,188,57,210,236,158,165,100,63,19,124,84,63,152,247,46,10,89,84,64,249,108,85'],
        expectedOutput: '0x692839b8,0x956bced2,0xd2fd728c,0xc33cae4a'
      },
      {
        input: ['153,32,51,17,127,174,216,84,101,148,141,56,128,43,221,229,106,240,97,190,47,249,181,93,4,15,178,68,8,30,153,161,62,205,179,190,123,139,18,225,31,160,25,159,203,246,132,54,230,230,244,21,223,170,114,227,185,36,40,193,67,193,99,129'],
        expectedOutput: '0x4cab152f,0x228be2e0,0x50bf9a95,0x10018c64'
      },
      {
        input: ['142,22,63,10,161,82,235,192,242,4,95,189,250,228,243,224,202,232,245,169,146,103,141,75,140,181,12,207,118,111,80,5,133,144,15,38,226,250,230,212,254,70,145,248,42,133,216,244,109,205,157,255,52,42,74,192,223,86,143,86,198,224,91,75'],
        expectedOutput: '0x10acccac,0x294acef6,0xc8b8807d,0x37161afc'
      },
      {
        input: ['112,106,114,82,100,88,38,98,158,183,90,200,60,50,188,169,255,90,168,51,132,242,244,100,73,131,186,15,99,21,90,211,127,204,37,227,37,75,69,195,3,159,140,63,209,72,233,208,162,145,3,39,132,247,139,205,123,69,220,222,90,54,178,217'],
        expectedOutput: '0x0b985697,0x03763164,0xfa8fff58,0xd0e8f525'
      },
      {
        input: ['3,215,188,40,35,1,235,38,160,119,101,113,192,78,65,98,224,68,137,100,60,20,49,183,89,13,149,179,67,71,140,70,31,72,110,66,73,90,104,233,209,205,90,145,28,155,244,252,224,125,96,28,146,145,211,235,158,104,159,225,176,43,40,207'],
        expectedOutput: '0x2eb202c8,0xe5dc7386,0x93dc594c,0x5e76cff4'
      },
      {
        input: ['116,150,17,189,240,121,167,194,70,1,83,98,157,71,94,125,197,190,153,87,79,108,66,237,212,225,207,132,13,247,83,129,141,100,62,126,221,229,64,36,231,147,134,132,219,229,1,160,163,154,247,243,6,57,224,218,27,175,95,40,166,178,169,52'],
        expectedOutput: '0x09ca26dc,0xecbc9ecc,0x35b8485f,0xc3927f5d'
      },
      {
        input: ['23,231,178,244,205,242,24,180,133,159,56,96,132,57,0,39,211,247,26,217,49,251,179,76,170,18,116,81,197,29,133,220,4,55,208,209,41,233,133,174,136,189,15,12,246,15,51,201,7,78,162,56,73,86,132,243,104,248,68,45,21,201,9,25'],
        expectedOutput: '0xc5a87dca,0xdce179e0,0xe18ae6b2,0x90892264'
      },
      {
        input: ['0,218,235,41,195,112,216,75,46,231,87,36,246,138,238,253,216,144,53,33,230,185,21,79,177,89,124,198,35,134,224,35,96,203,77,35,59,37,110,105,12,197,142,2,79,124,0,40,12,53,73,243,239,94,66,160,184,190,103,219,68,71,254,164'],
        expectedOutput: '0xd6534748,0x4f79524b,0xacf5b71c,0x34e6388d'
      },
      {
        input: ['18,75,199,77,112,53,183,124,250,69,127,74,193,127,114,205,180,187,192,163,26,2,68,210,193,171,173,5,242,171,170,4,247,113,81,103,167,8,228,161,77,99,235,14,226,93,220,150,25,156,58,51,159,126,5,96,41,178,101,27,93,15,31,84'],
        expectedOutput: '0x5d50ec96,0x2f746077,0xf366df08,0x5adb58c9'
      },
      {
        input: ['129,112,188,40,121,160,201,198,3,181,213,229,18,177,123,43,77,181,94,236,51,99,76,92,21,178,119,115,193,150,199,66,7,131,106,128,35,52,70,38,233,27,11,251,204,135,39,26,60,133,6,112,233,83,204,254,5,68,113,198,218,57,9,225'],
        expectedOutput: '0x0f309ad8,0x645e6c99,0xc218d33f,0xa450017c'
      },
      {
        input: ['188,115,97,224,167,168,6,144,195,18,140,144,153,179,170,213,56,176,69,33,3,18,32,8,86,145,207,48,202,216,18,135,75,115,103,243,27,109,131,223,127,15,111,24,194,25,238,251,201,51,28,205,69,60,213,155,206,164,204,152,124,222,31,200'],
        expectedOutput: '0xf79baf53,0x6bedff11,0x2ea0829b,0xf1e11121'
      },
      {
        input: ['81,134,187,109,244,62,76,115,78,187,140,16,212,122,11,157,173,40,106,243,100,64,142,50,228,90,203,97,56,234,41,138,113,228,247,101,34,67,216,112,254,100,129,210,222,140,111,140,180,218,127,25,26,13,75,254,104,22,95,160,1,136,42,114'],
        expectedOutput: '0xd0bede5a,0xfa919b57,0x7c5b3197,0xa1684e86'
      },
      {
        input: ['108,33,215,143,100,175,255,98,20,128,52,242,13,164,126,193,126,253,218,152,11,38,150,115,60,246,19,61,126,62,175,235,95,134,122,196,54,121,38,74,250,91,60,7,255,187,200,125,184,163,21,195,201,171,54,5,161,74,67,32,136,242,11,231'],
        expectedOutput: '0x8e78b5f0,0x6201a1d9,0xe0ea6007,0x13b3ce9a'
      },
      {
        input: ['121,133,171,175,254,210,249,248,45,53,255,44,240,200,169,169,107,190,108,52,105,163,57,11,237,124,43,117,111,54,92,232,187,8,151,185,218,144,178,7,197,177,51,182,121,220,95,228,154,203,24,3,110,82,14,91,206,57,208,61,111,45,37,42'],
        expectedOutput: '0xfde23061,0x4e555355,0xce7fc58c,0x94ed0708'
      },
      {
        input: ['53,188,228,15,76,150,22,18,71,73,200,193,37,39,165,191,242,190,194,97,16,209,188,222,10,141,28,122,186,65,164,239,254,136,254,74,30,20,92,102,93,36,39,130,75,204,65,62,138,3,159,154,212,91,121,223,232,149,89,162,214,253,145,212'],
        expectedOutput: '0xaff0f9e6,0x8b7142a0,0xef762899,0x2c6e124e'
      },
      {
        input: ['134,143,31,164,163,123,10,0,160,49,130,235,254,195,41,136,199,200,35,155,36,156,122,12,49,211,175,7,209,64,220,87,208,251,251,115,118,6,116,22,55,246,2,53,186,43,190,129,244,225,28,24,125,151,36,174,106,211,181,59,20,145,146,228'],
        expectedOutput: '0x0f008bfe,0x41824d30,0x382ba6e6,0xd60f68db'
      },
      {
        input: ['140,142,87,3,148,203,25,203,194,27,1,124,71,191,253,59,160,25,83,29,176,119,203,27,75,128,86,95,18,233,67,158,119,154,161,11,102,187,214,40,214,215,164,29,150,161,88,54,186,171,83,107,35,30,134,110,159,220,205,177,197,16,79,60'],
        expectedOutput: '0xad01687c,0x108eb88d,0x258e145c,0xb6d32ea8'
      },
      {
        input: ['170,241,71,16,172,30,56,130,245,220,160,140,125,248,194,56,164,22,163,199,52,41,53,211,5,2,132,203,18,212,7,188,197,79,205,113,109,5,243,98,226,147,238,95,140,177,151,48,199,58,247,251,99,44,207,105,46,83,52,64,39,59,252,236'],
        expectedOutput: '0x1e2a4fb4,0x08ded36b,0x6ffdd0b1,0xbb10afff'
      },
      {
        input: ['138,201,93,247,207,81,90,177,228,72,16,112,249,168,160,192,226,151,188,70,195,139,175,241,222,227,49,6,30,46,242,169,247,80,160,198,161,250,119,133,67,136,246,60,48,150,253,18,46,185,88,241,68,7,227,34,234,20,40,9,66,27,178,58'],
        expectedOutput: '0xbcd3eb60,0x64eb6148,0xacf44aad,0xefdf1c6e'
      },
      {
        input: ['107,82,0,12,77,120,145,144,0,135,204,48,30,201,66,76,130,155,61,198,162,32,233,141,53,17,150,119,44,72,177,151,154,178,163,231,42,53,119,42,188,68,90,218,13,156,38,144,55,100,86,218,132,63,103,185,81,253,49,125,69,226,21,223'],
        expectedOutput: '0x234ddf1b,0x09a9ccf4,0x4d2383c3,0x1eab2418'
      },
      {
        input: ['148,184,199,190,237,62,232,170,130,66,132,144,223,171,32,22,15,118,240,147,182,87,77,7,84,126,132,153,96,153,121,245,82,64,179,63,126,156,233,1,222,110,145,189,25,177,212,40,39,196,187,221,28,8,228,112,134,105,10,231,2,131,220,84'],
        expectedOutput: '0xb174305b,0x34a2a239,0xd2cc62be,0x6d1ee028'
      },
      {
        input: ['195,143,148,65,43,125,66,10,235,211,199,4,132,155,44,172,96,232,137,124,240,110,236,119,215,246,94,217,121,58,46,60,201,194,126,245,63,192,255,43,148,198,47,24,98,92,196,194,68,78,62,52,188,42,171,147,33,9,108,154,67,154,215,13'],
        expectedOutput: '0xcc7e9f48,0x92838320,0x28c1fef9,0x72122553'
      },
      {
        input: ['92,85,2,156,21,1,199,169,199,246,194,41,82,134,235,150,212,41,203,144,84,118,35,117,128,144,15,195,42,230,208,135,59,210,35,81,211,234,250,155,224,188,196,51,67,176,201,23,217,148,168,45,11,203,162,139,91,178,78,134,152,31,13,212'],
        expectedOutput: '0x09f95e40,0x7a2ea504,0x19342fff,0x0fff4739'
      },
      {
        input: ['241,48,37,197,26,31,96,250,220,36,45,31,212,247,54,174,139,222,219,150,170,126,33,5,48,112,139,200,143,152,156,128,200,193,69,226,225,165,221,189,202,10,220,158,1,18,76,141,241,40,35,155,166,69,160,214,181,44,158,68,196,59,196,141'],
        expectedOutput: '0x8fda73e0,0x5741519e,0xc6cdb7da,0xda4a78fa'
      },
      {
        input: ['252,10,111,221,175,76,154,121,87,118,24,88,137,100,229,122,140,9,21,50,78,181,8,3,225,167,71,166,226,11,51,222,21,162,188,197,239,86,62,70,205,86,158,86,187,132,208,71,141,229,122,219,154,130,222,124,41,37,34,11,48,85,234,70'],
        expectedOutput: '0x7e03e36a,0x13fe4f4a,0xd8ae6cc4,0xf8e58743'
      },
      {
        input: ['247,166,11,230,252,73,44,201,160,203,31,91,79,239,162,220,212,28,183,111,159,149,235,200,186,13,212,234,98,190,48,89,100,59,64,96,133,108,42,37,55,73,128,134,57,34,98,13,63,25,124,222,174,103,166,104,116,122,83,214,56,131,48,156'],
        expectedOutput: '0x14be2d31,0xcbb52424,0x143b253a,0xdb2d4e11'
      },
      {
        input: ['191,112,253,68,220,39,105,20,112,233,154,169,11,253,183,74,22,51,40,197,155,207,45,15,73,128,230,130,4,22,30,195,134,27,7,98,66,112,118,179,89,17,92,100,14,19,175,36,71,215,233,226,166,23,241,240,151,215,114,155,237,144,94,115'],
        expectedOutput: '0x8ee53de3,0xe95c167f,0x83e1bfaa,0x874d05ac'
      },
      {
        input: ['172,101,214,238,213,76,161,46,93,254,147,107,17,66,144,88,25,121,58,192,144,44,176,40,3,34,195,241,178,34,100,94,135,58,77,93,135,238,139,228,236,30,80,254,96,224,86,122,89,145,58,234,189,234,18,192,12,213,177,190,247,22,29,127'],
        expectedOutput: '0xf1534b55,0xbb80bb45,0x082bd3f9,0x760422f1'
      },
      {
        input: ['80,106,220,215,88,103,188,69,134,12,67,230,236,153,96,69,42,154,47,231,132,65,168,144,23,89,79,14,111,108,141,192,214,105,151,46,209,83,115,87,95,182,61,75,80,158,145,122,56,192,98,189,2,10,77,25,99,156,39,211,8,181,147,222'],
        expectedOutput: '0xe0e05200,0xd9b3e5c8,0x750ea5be,0xe2dc1bd6'
      },
      {
        input: ['30,42,13,239,126,128,70,221,55,132,41,135,34,186,1,90,122,99,23,124,109,101,149,209,1,189,164,10,114,55,232,144,97,245,128,223,118,198,189,173,74,230,52,108,160,53,199,26,153,222,151,6,67,44,215,69,233,123,79,91,178,55,236,20'],
        expectedOutput: '0xcae185b6,0x64141e9b,0x505bb9ab,0x34d466fa'
      },
      {
        input: ['45,108,243,163,50,176,80,125,150,132,233,54,185,176,81,82,143,232,89,210,20,48,23,254,172,102,89,94,158,69,114,203,177,102,110,228,22,190,97,173,66,74,227,251,251,52,78,138,28,167,92,49,215,116,47,131,218,136,226,120,206,84,67,127'],
        expectedOutput: '0x28b19e21,0xf912c859,0x2329ca8f,0xa007b1d9'
      },
      {
        input: ['186,177,99,209,111,196,126,177,15,97,173,10,150,251,148,178,162,240,227,121,100,18,253,63,155,223,183,105,51,251,232,238,172,76,191,28,16,61,205,31,158,122,41,52,117,189,231,23,174,202,145,18,221,142,81,120,109,9,225,160,4,201,142,176'],
        expectedOutput: '0x140c4fd9,0x8515a521,0x7531de15,0x3c514957'
      },
      {
        input: ['21,77,204,38,138,154,69,41,20,111,93,138,44,68,161,218,15,50,237,236,192,62,100,45,71,69,206,75,14,92,252,36,170,200,74,52,98,143,93,119,254,187,1,43,255,162,5,14,213,242,250,149,49,94,195,120,163,145,196,178,237,192,214,151'],
        expectedOutput: '0x015a111e,0x58879a4b,0x023bad62,0x9b086886'
      },
      {
        input: ['136,32,204,235,175,41,98,174,228,99,217,228,5,222,242,218,209,237,112,2,75,51,122,239,196,62,161,177,254,119,73,135,151,21,114,70,62,212,244,35,55,205,7,60,172,249,23,125,230,135,127,50,186,249,33,126,56,194,47,54,57,120,189,208'],
        expectedOutput: '0x574a4d6c,0xb6936404,0x1f170d12,0x76e57476'
      },
      {
        input: ['141,47,22,204,3,11,239,58,216,246,119,132,239,142,1,214,21,128,8,207,122,41,77,178,235,124,232,36,245,166,244,130,213,10,78,217,21,61,19,238,51,138,114,35,24,116,249,45,244,1,252,110,42,73,32,21,198,9,57,187,175,45,61,132'],
        expectedOutput: '0xc4387a64,0xd9cd64d3,0x7ca61d4a,0xdfc9470f'
      },
      {
        input: ['55,140,93,77,201,113,59,253,251,173,32,20,33,25,65,22,26,62,132,68,135,165,89,77,174,146,8,93,191,70,225,246,210,63,67,155,176,126,152,171,44,184,191,77,209,1,99,235,63,232,47,198,141,136,20,59,26,28,152,217,98,121,208,52'],
        expectedOutput: '0x973157d4,0x5117aad9,0xf1debc89,0x0414afcc'
      },
      {
        input: ['184,19,208,104,146,104,20,190,33,211,11,242,212,111,222,19,87,13,218,228,150,238,31,176,10,183,138,109,48,90,161,233,109,113,81,255,218,101,189,251,57,201,237,13,56,203,33,143,217,251,115,111,233,146,31,243,73,169,96,121,3,2,98,113'],
        expectedOutput: '0x9f2386d1,0x204c7cdd,0x55546295,0x0298da37'
      },
      {
        input: ['115,180,112,77,25,46,72,82,247,54,96,47,1,129,190,218,124,49,73,101,195,105,88,12,18,185,133,22,187,232,135,46,156,247,124,181,37,196,8,28,250,104,75,252,233,9,214,101,58,32,202,253,137,34,9,155,219,143,177,150,119,56,197,19'],
        expectedOutput: '0xd1727a5e,0xe33afe9b,0x7c8ba189,0xe6dbe63e'
      },
      {
        input: ['48,65,200,85,5,208,114,0,56,189,252,33,199,210,134,1,242,80,255,123,115,8,23,78,151,200,229,14,1,170,33,49,235,234,134,240,186,248,240,243,182,236,20,125,191,155,126,177,235,125,45,94,134,68,173,29,12,146,44,13,60,77,62,39'],
        expectedOutput: '0x171f0524,0xe03fdab1,0x57c4ccec,0xa4b895fa'
      },
      {
        input: ['55,197,23,242,189,8,229,115,244,249,240,179,148,111,101,128,236,146,222,114,214,139,144,226,29,188,240,89,9,46,128,65,243,152,51,177,160,24,36,148,17,21,72,166,132,173,38,112,63,4,227,21,144,115,247,173,47,231,7,56,22,135,121,9'],
        expectedOutput: '0x1400d00d,0xffeff449,0x972a6a12,0xb628340e'
      },
      {
        input: ['31,172,186,191,196,223,84,214,244,156,124,120,73,162,232,136,166,203,157,54,62,148,228,109,124,235,166,146,114,31,155,146,204,86,81,144,53,165,102,41,65,226,161,138,132,137,18,43,85,175,97,147,68,69,1,192,48,167,82,163,198,237,53,146'],
        expectedOutput: '0x34868fdc,0xa69d8da7,0x7a389d43,0x79766177'
      },
      {
        input: ['67,134,35,120,44,137,161,109,108,66,248,240,204,10,27,33,186,125,180,254,194,181,190,243,92,16,150,35,253,203,181,65,81,216,185,125,98,91,235,206,157,227,190,105,237,218,138,167,87,63,165,25,244,99,12,81,115,162,116,113,109,41,178,191'],
        expectedOutput: '0x94294bf9,0x651a2ffe,0x172ab41b,0xa37a1e1f'
      },
      {
        input: ['2,107,60,100,198,39,50,100,10,240,205,248,202,88,159,33,151,69,59,139,168,71,220,28,234,80,141,87,122,63,22,124,170,83,224,113,122,18,213,133,2,162,125,205,250,28,238,145,97,41,29,10,113,249,38,91,74,179,178,196,242,201,64,156'],
        expectedOutput: '0x5750fcee,0xdd84159c,0xbddb91a9,0x06e65c0a'
      },
      {
        input: ['28,32,13,150,50,226,27,52,133,152,1,127,181,240,17,22,25,46,32,138,39,70,229,113,249,152,53,235,97,117,136,125,149,149,19,199,120,47,252,253,199,253,124,124,237,141,147,7,187,179,145,227,250,119,84,243,15,138,223,112,255,103,237,149'],
        expectedOutput: '0xc8bc8be7,0x71c66866,0xff270d2f,0xcd114591'
      },
      {
        input: ['252,0,92,116,47,88,113,247,86,238,115,67,123,6,74,55,186,220,26,180,83,110,167,98,248,134,210,248,237,191,141,234,191,233,94,239,66,208,230,152,190,89,219,57,96,38,112,26,2,138,206,85,249,117,183,241,252,137,233,233,72,118,211,7'],
        expectedOutput: '0x70db9822,0x4964a6f5,0xcd260b76,0xd9f65b72'
      },
      {
        input: ['96,50,246,162,2,220,58,192,54,21,249,150,59,106,176,61,244,126,146,237,243,73,223,239,210,200,217,26,63,172,34,159,222,24,65,224,245,123,160,43,144,154,193,204,4,113,9,248,239,156,230,226,229,197,210,184,141,171,210,204,87,244,107,54'],
        expectedOutput: '0x59386d2c,0xc1b6d8b5,0x8176c1b7,0xd40b3e26'
      },
      {
        input: ['13,172,22,2,39,183,45,184,81,238,132,85,95,141,77,78,41,51,48,15,248,2,199,134,173,153,82,5,142,190,59,155,106,81,157,146,8,202,74,89,184,206,174,23,91,252,101,133,47,149,148,40,152,91,174,69,244,0,74,130,190,133,29,41'],
        expectedOutput: '0xd5eea224,0x043ae1bc,0x711adc1e,0xaf50f543'
      },
      {
        input: ['215,186,187,223,132,5,57,60,211,231,83,46,227,184,179,19,78,71,59,230,162,233,43,151,233,118,25,168,251,55,209,210,241,140,178,118,145,235,178,100,210,6,146,182,190,70,201,12,141,4,242,48,237,30,199,214,148,224,126,143,23,79,98,9'],
        expectedOutput: '0x01164410,0x29ecac31,0xbd7a79da,0x7d78b589'
      },
      {
        input: ['219,20,127,108,255,49,208,209,55,99,135,246,169,80,2,54,84,245,102,65,19,45,24,167,14,150,54,37,230,152,46,193,172,173,46,171,223,254,125,22,97,4,12,10,85,15,65,169,4,167,235,23,213,3,190,227,153,244,8,127,141,55,65,57'],
        expectedOutput: '0xf61549eb,0xdfb7a819,0xc378c4dc,0xa84bd684'
      },
      {
        input: ['228,111,229,195,109,98,218,207,102,230,217,187,245,26,101,249,194,80,16,151,83,206,122,236,195,130,108,80,185,173,137,158,28,110,97,137,208,59,88,55,34,50,242,23,76,87,17,14,167,33,165,250,240,31,231,179,162,83,3,91,0,140,249,28'],
        expectedOutput: '0xee44d9e4,0x74b726b6,0x806f3dca,0x19c038a2'
      },
      {
        input: ['251,91,165,203,150,254,2,184,48,245,208,124,76,225,139,244,2,48,238,242,80,213,165,242,40,168,77,40,53,71,68,48,162,234,251,56,232,254,241,24,243,193,148,63,162,31,51,164,80,34,151,160,247,60,146,32,229,223,72,26,38,141,74,200'],
        expectedOutput: '0x57536ebf,0x97df50ff,0x22289e54,0x08080469'
      },
      {
        input: ['119,69,1,95,67,242,119,54,179,11,118,85,43,169,249,123,203,144,27,195,205,173,227,178,140,43,204,179,184,22,123,47,91,124,142,159,110,5,213,33,17,75,118,60,245,112,183,192,0,210,131,205,127,102,127,11,146,75,190,74,97,58,122,189'],
        expectedOutput: '0xf4a4e0f0,0x6bb2433a,0x946cbad6,0xd8b4b6c7'
      },
      {
        input: ['182,8,92,37,14,49,70,31,125,189,91,114,45,18,50,45,228,182,251,99,28,122,110,174,198,45,249,39,103,115,228,29,123,64,66,137,114,137,168,239,70,3,97,115,21,147,160,249,73,155,92,102,22,203,20,220,248,13,3,95,128,232,124,252'],
        expectedOutput: '0xfac26b4d,0x4f00c6bd,0x9f7bb701,0xa5d5c219'
      },
      {
        input: ['40,191,133,154,72,46,137,142,49,234,1,71,126,161,64,199,61,157,45,83,104,66,47,96,79,50,191,208,26,59,204,67,250,81,221,66,127,103,208,177,81,209,248,207,115,56,151,176,213,196,3,61,6,50,157,86,100,92,38,127,152,242,194,146'],
        expectedOutput: '0x89fc004a,0x17684700,0x8b1141f8,0xff1bafb7'
      },
      {
        input: ['67,159,213,195,6,165,116,88,119,108,39,234,164,190,154,122,131,157,183,137,207,85,223,51,177,5,178,73,247,116,220,59,20,177,254,26,86,114,114,205,222,154,183,130,88,81,252,219,238,180,101,189,9,68,241,186,74,163,4,65,24,224,124,44'],
        expectedOutput: '0xba76cd1b,0x993bcba1,0x859c0f0b,0x24e0341f'
      },
      {
        input: ['145,122,70,231,236,185,181,202,83,108,77,171,190,73,135,172,253,236,106,6,48,91,193,122,254,197,188,22,165,56,66,54,179,137,29,159,66,210,106,149,63,183,64,253,0,199,169,254,179,19,4,228,110,197,94,109,138,26,131,47,83,198,101,6'],
        expectedOutput: '0x96a98ef4,0x82c6c227,0xb11ac633,0xc1bee240'
      },
      {
        input: ['79,131,165,145,85,15,38,148,198,102,145,199,46,59,197,225,78,201,197,189,143,36,42,25,62,173,73,145,115,174,151,194,49,61,83,135,76,121,27,19,224,173,218,14,232,159,239,54,104,181,243,247,217,29,17,23,203,90,169,62,8,64,1,58'],
        expectedOutput: '0xbed2f7d3,0x9f716d46,0xd066d4db,0x28d32c4d'
      },
      {
        input: ['125,84,193,202,206,220,221,174,137,183,188,113,86,171,168,190,96,155,182,57,185,199,81,132,33,250,194,41,58,195,99,184,24,36,130,230,1,95,148,138,22,80,252,108,251,164,42,92,63,224,149,248,167,230,124,200,224,63,242,27,2,85,211,26'],
        expectedOutput: '0xcb89ccb8,0x6bc5eac2,0x9e3327f3,0x7f06ab0b'
      },
      {
        input: ['122,85,0,123,180,148,5,202,228,1,54,224,165,96,60,229,65,209,221,232,184,90,177,152,153,163,179,155,248,134,182,114,219,182,237,143,75,243,89,47,244,143,15,154,240,75,127,49,29,92,25,213,182,202,109,79,109,33,235,102,167,161,216,131'],
        expectedOutput: '0x2ec67e6f,0x46164f34,0x8dc1e893,0xb4a10ba0'
      },
      {
        input: ['87,198,18,162,185,108,210,173,251,225,71,235,45,198,28,74,35,54,31,217,0,140,41,110,173,20,212,85,181,172,216,12,114,234,175,43,86,129,217,82,98,32,61,143,231,90,217,10,144,248,227,144,133,12,254,50,32,210,135,213,127,95,226,241'],
        expectedOutput: '0xadc4e6ed,0x58a20191,0x4b3164f8,0x6b211d40'
      },
      {
        input: ['74,145,29,160,18,246,242,116,22,48,4,253,138,221,7,26,214,235,170,91,247,169,141,24,123,21,237,250,116,207,236,190,96,9,95,114,255,81,231,21,129,235,19,11,200,26,37,158,5,208,249,253,121,135,21,244,156,2,239,16,210,219,207,50'],
        expectedOutput: '0x998e8887,0xcd821cb0,0x03d1c642,0x5dbc574e'
      },
      {
        input: ['228,46,165,227,127,140,248,1,119,11,12,63,38,50,222,43,2,215,40,123,94,61,111,250,64,94,11,18,57,218,68,29,8,233,0,135,117,249,136,236,4,149,44,42,199,10,86,201,225,126,68,64,188,179,58,252,18,69,14,75,31,82,105,39'],
        expectedOutput: '0x1b2c7f97,0x302db482,0xeae63c32,0xece1ea5c'
      },
      {
        input: ['60,105,175,177,98,55,158,103,204,202,145,147,212,231,92,181,102,160,245,34,84,48,30,102,117,44,177,149,126,26,188,186,132,107,108,230,163,10,77,111,212,223,3,168,198,95,93,44,0,83,78,84,131,108,186,248,152,107,141,23,134,74,209,10'],
        expectedOutput: '0x1d54afe8,0xb6b18a7e,0x3e72b4f7,0xb828b03e'
      },
      {
        input: ['181,61,240,88,71,62,200,27,29,203,195,227,42,33,16,42,116,94,126,247,203,56,239,99,164,125,122,42,199,76,52,124,137,36,213,209,98,157,236,127,104,176,99,146,209,115,189,69,209,59,60,156,116,43,0,24,168,122,66,111,198,118,236,80'],
        expectedOutput: '0x01813a47,0xe591e608,0x3b2e63c6,0xf04bf009'
      },
      {
        input: ['154,193,33,253,94,13,124,198,189,223,88,142,82,21,211,36,81,15,192,197,59,192,221,227,59,31,83,1,149,63,81,47,0,114,44,94,128,169,36,61,136,124,204,219,146,159,255,227,175,191,168,234,128,133,205,187,164,32,188,57,95,14,104,95'],
        expectedOutput: '0x6d8a966a,0xfc5c6367,0x5114c6c0,0x66ee65aa'
      },
      {
        input: ['128,149,189,0,62,225,62,198,94,10,161,240,169,160,211,88,96,123,66,224,0,16,155,164,48,87,221,144,101,69,239,230,218,173,230,24,142,36,223,236,46,128,220,216,33,175,48,129,42,115,97,42,131,252,206,179,83,171,67,185,241,51,159,203'],
        expectedOutput: '0xbd274048,0xf53c1a7e,0xd2d2c358,0xa41bb8a1'
      },
      {
        input: ['224,133,228,110,170,195,91,216,67,55,176,100,231,225,229,17,84,70,60,215,66,10,138,150,182,206,79,167,1,238,114,225,115,86,79,29,25,170,246,93,226,166,193,201,135,167,218,219,237,22,178,48,33,61,198,215,11,21,126,12,3,240,237,118'],
        expectedOutput: '0x10aae87a,0x2de79b4e,0x748c6804,0xc23ff5f9'
      },
      {
        input: ['71,60,148,96,231,138,189,201,48,127,146,184,38,108,147,19,131,70,67,164,131,9,123,142,30,249,154,33,233,135,152,48,195,44,145,170,182,78,115,230,205,5,158,243,114,50,7,245,120,74,153,251,84,20,137,114,13,35,148,246,170,44,39,109'],
        expectedOutput: '0x23f1b3b6,0x8636e55b,0x1fb25f25,0x3d2a22c4'
      },
      {
        input: ['88,184,24,14,6,139,244,212,145,147,199,3,197,206,248,61,25,145,56,109,165,193,223,178,228,115,168,142,159,207,251,247,135,19,5,142,159,250,98,48,141,41,51,82,248,43,143,17,188,199,126,97,136,93,19,108,209,187,250,112,139,245,104,18'],
        expectedOutput: '0x5b73602f,0xfb97e668,0xc29f9194,0xa3d01a9b'
      },
      {
        input: ['9,109,160,168,103,2,216,244,44,11,70,36,54,213,53,242,156,179,83,36,16,102,144,225,33,138,82,172,128,186,191,137,39,95,49,143,98,9,131,142,20,202,178,74,159,231,60,60,154,143,96,170,245,241,140,22,123,222,195,251,152,130,132,191'],
        expectedOutput: '0xae24bff8,0x8c90f6fd,0x082eb95c,0x3844a04c'
      },
      {
        input: ['225,181,78,67,190,210,209,210,156,131,28,59,106,88,119,4,231,216,175,220,201,59,243,68,25,182,64,177,56,196,112,25,122,191,93,56,145,46,11,45,178,39,104,28,128,224,33,103,184,208,68,129,11,55,197,36,237,5,213,37,202,69,62,68'],
        expectedOutput: '0xe101e8df,0xa8b6e3eb,0x728803f9,0x8de1ac79'
      },
      {
        input: ['4,155,124,149,202,135,194,124,175,43,152,47,11,185,150,195,137,218,68,148,17,9,184,254,15,141,35,217,211,98,29,215,253,153,109,199,33,47,67,208,90,220,255,101,149,149,40,31,112,108,179,129,118,108,128,133,249,163,94,204,5,123,164,3'],
        expectedOutput: '0xc148b816,0xdccf6f2c,0xb3674592,0x2965f0ca'
      },
      {
        input: ['20,17,202,53,64,14,5,155,234,4,0,127,154,41,158,10,149,82,139,11,190,11,144,183,175,238,132,180,105,40,183,126,57,130,179,121,144,185,20,122,189,21,249,87,62,152,97,211,234,237,223,168,248,111,95,167,94,227,92,199,11,19,69,68'],
        expectedOutput: '0x949f98c8,0x82622a6e,0x21f5eb8f,0x39b031ed'
      },
      {
        input: ['149,249,190,37,178,210,159,111,231,153,199,37,49,40,249,27,21,216,195,14,71,34,181,165,6,17,109,17,37,178,86,186,171,20,224,93,230,127,205,206,24,148,243,73,188,236,100,210,196,39,224,12,74,149,177,80,167,30,97,204,209,183,134,124'],
        expectedOutput: '0x9ec54c5f,0x8cb4cdff,0x39ca68ff,0xc0e3836b'
      },
      {
        input: ['203,102,218,178,230,167,128,254,59,115,72,247,96,172,201,36,212,169,48,30,63,226,110,230,0,207,178,209,135,56,78,82,159,40,4,133,207,132,131,10,248,203,1,88,120,203,124,76,116,173,106,179,143,216,153,143,167,75,97,46,132,175,129,35'],
        expectedOutput: '0xd034960c,0x92b84077,0xae865c02,0x13dba90c'
      },
      {
        input: ['215,133,168,166,10,43,176,2,247,177,90,111,124,214,187,241,131,37,164,18,253,62,162,164,137,3,211,13,178,84,48,137,217,216,47,227,4,223,229,251,144,63,106,13,22,37,254,153,74,162,172,71,224,78,235,106,81,190,119,3,18,168,140,236'],
        expectedOutput: '0x9310cce9,0x5d0e1391,0x670fcab3,0x7496aa2d'
      },
      {
        input: ['128,187,207,132,154,181,127,42,244,233,55,10,14,53,164,88,216,80,159,184,158,139,34,239,73,154,242,92,66,126,72,194,57,23,71,211,204,198,253,193,176,53,203,190,106,111,23,66,191,182,251,93,65,29,76,139,183,62,231,249,188,47,188,245'],
        expectedOutput: '0xd32fb206,0x515d16f5,0xdbbfb2cf,0x99aa5570'
      },
      {
        input: ['70,3,200,19,201,198,212,121,251,159,56,101,15,79,168,206,5,163,44,71,192,120,210,120,183,185,113,115,232,45,105,46,48,49,65,250,247,21,115,242,181,171,88,196,250,0,146,0,163,190,71,99,55,25,219,238,210,77,97,186,122,202,232,171'],
        expectedOutput: '0x00dc763e,0x22983b86,0xe99d8a43,0x81f7f69c'
      },
      {
        input: ['252,42,165,243,63,24,230,244,196,62,184,190,62,75,190,225,9,5,68,64,30,32,46,240,109,144,170,231,90,147,146,86,189,55,74,252,80,48,241,20,110,169,210,172,244,145,141,254,150,209,62,181,241,109,165,94,253,80,70,87,227,216,174,160'],
        expectedOutput: '0x9398674b,0xdccf3b59,0x9295afa3,0xaa0c4924'
      },
      {
        input: ['16,248,156,96,40,141,116,150,55,70,66,43,215,207,41,110,160,104,35,146,213,200,240,210,24,54,41,251,15,215,155,31,207,56,127,247,197,243,141,252,57,207,40,17,158,81,127,63,185,162,209,142,106,193,96,131,248,138,126,7,97,26,38,49'],
        expectedOutput: '0xefbdda1e,0xe8976a15,0x7fb131ed,0xda6142e0'
      },
      {
        input: ['82,165,40,23,152,182,20,209,133,60,226,36,141,97,99,71,3,52,213,110,245,54,241,237,192,111,244,33,137,26,82,219,191,123,243,87,49,7,41,182,67,11,218,208,109,61,23,112,113,237,222,103,35,207,84,227,63,73,4,200,99,87,164,35'],
        expectedOutput: '0x15af5dc1,0xabcb48ac,0xa49f6267,0x1b86822f'
      },
      {
        input: ['210,151,122,3,158,163,185,225,175,148,177,28,209,201,140,67,182,107,170,217,58,254,188,121,71,192,66,171,23,230,206,233,125,72,236,27,236,166,252,155,58,173,183,11,118,67,78,44,174,248,5,233,247,193,98,62,130,164,233,153,138,183,131,7'],
        expectedOutput: '0x774e28eb,0x67c054af,0xc3dbd93b,0xaebaa255'
      },
      {
        input: ['0,111,34,236,21,30,135,79,204,62,91,66,129,169,111,48,162,116,25,153,54,123,215,184,32,193,81,170,120,212,178,120,68,212,100,89,243,235,169,191,41,4,1,171,173,112,219,79,229,244,232,27,111,192,211,143,129,36,58,249,249,236,114,61'],
        expectedOutput: '0xac565815,0xc7e04f82,0x5bf38b3a,0x93052afe'
      },
      {
        input: ['192,214,150,179,194,63,114,235,67,116,150,241,228,113,64,201,101,41,228,213,233,183,100,106,220,158,99,213,138,213,18,75,172,168,254,110,232,113,89,43,229,240,28,201,97,93,147,199,134,119,156,111,47,0,217,11,159,60,224,41,18,242,116,190'],
        expectedOutput: '0x1142ca62,0x3f9683b8,0x5dab3000,0xd4e194f9'
      },
      {
        input: ['154,115,44,130,228,133,174,201,117,202,146,215,39,37,158,173,157,58,28,204,58,245,215,217,50,183,3,68,169,119,2,67,234,46,198,206,179,116,151,41,62,42,0,102,79,158,19,236,216,48,184,18,37,143,236,87,70,239,155,239,102,157,51,81'],
        expectedOutput: '0xdf8553df,0xa8b73855,0x56ca8aba,0xec36705d'
      },
      {
        input: ['203,249,31,127,109,183,168,171,225,168,17,48,70,37,29,30,85,213,48,122,101,28,210,171,11,109,155,114,11,206,195,214,199,226,85,52,153,253,223,122,165,241,171,235,22,200,9,107,157,58,229,2,86,183,174,98,37,73,212,48,23,151,6,222'],
        expectedOutput: '0x3e96c393,0x58e80975,0x41f1d62f,0xae5a4783'
      },
      {
        input: ['121,92,18,19,89,241,141,255,226,56,234,248,0,244,99,158,46,73,160,132,0,78,230,37,151,186,85,174,81,92,140,203,184,158,222,17,144,107,16,114,164,251,107,164,239,206,66,29,23,227,161,24,49,136,61,201,66,147,119,148,239,4,95,167'],
        expectedOutput: '0x0e6ea29c,0xec38ebc8,0x154f0ba7,0xe4a5ee50'
      },
      {
        input: ['162,61,184,50,168,201,165,76,196,16,241,179,222,51,208,246,22,113,14,72,249,75,17,60,222,136,208,205,140,47,116,47,108,45,97,20,246,6,97,186,22,82,109,245,133,61,235,156,174,249,228,168,68,245,228,35,125,180,240,10,227,101,57,79'],
        expectedOutput: '0x1586fd9a,0xa955e3fe,0xce3335b6,0x4dfbf36f'
      },
      {
        input: ['146,154,99,136,161,196,66,183,22,175,172,156,236,151,56,154,144,28,66,213,17,38,248,142,218,232,152,189,77,209,12,223,108,112,103,13,52,169,196,75,88,113,231,68,8,31,223,153,59,33,110,76,72,102,218,34,78,115,224,156,68,236,123,176'],
        expectedOutput: '0xf5fe000f,0xb4039012,0x0d75fb3e,0xca9dbc53'
      },
      {
        input: ['92,227,189,145,140,130,220,229,243,195,41,251,226,8,148,29,42,2,105,114,104,67,148,183,182,116,83,251,97,206,171,189,177,105,78,62,235,42,35,222,237,76,217,207,85,110,236,127,112,85,241,217,153,133,144,79,250,227,74,91,177,246,24,99'],
        expectedOutput: '0xf116b0b2,0x0bcceab6,0x9e52c9a8,0x0bda62fb'
      },
      {
        input: ['95,103,161,74,145,196,40,127,16,1,78,101,111,59,228,224,144,213,185,41,91,73,121,85,44,195,176,221,185,200,64,24,47,225,98,193,165,138,64,182,140,142,27,251,201,0,219,90,213,148,131,48,221,252,133,9,192,53,231,121,254,39,146,45'],
        expectedOutput: '0xd5ded80b,0x0dc6fcc9,0x38d8acba,0x661621d9'
      },
      {
        input: ['9,244,238,174,127,46,100,11,189,128,6,134,128,226,224,85,118,100,134,84,96,11,93,32,65,68,154,63,108,44,108,117,32,91,35,159,137,136,170,70,8,177,205,136,147,173,221,9,17,99,93,114,111,187,146,176,255,44,239,107,88,91,224,121'],
        expectedOutput: '0xd03bd0ee,0xa5206dd9,0x14908467,0x32d9b37e'
      },
      {
        input: ['182,4,24,64,140,195,134,148,116,83,28,7,1,249,16,18,93,110,132,204,41,23,124,40,67,107,148,156,198,116,21,125,120,45,189,4,240,67,152,100,151,180,107,152,174,124,170,11,234,47,215,19,70,83,59,137,190,207,37,132,68,58,1,188'],
        expectedOutput: '0x4a35e90d,0xa6266d18,0x78e07763,0xa1539f63'
      },
      {
        input: ['104,190,193,88,2,89,189,153,14,40,49,188,164,219,199,142,10,158,161,80,241,221,218,175,172,255,51,240,58,53,173,162,243,110,250,245,199,183,142,213,224,191,145,132,155,88,19,165,246,180,246,231,145,208,150,62,207,202,46,9,255,219,171,242'],
        expectedOutput: '0x011af52a,0x2a86977f,0x9d77c9c9,0xc0c7edf5'
      },
      {
        input: ['73,166,232,17,93,118,230,61,54,120,194,209,208,213,118,199,137,108,174,27,60,69,89,12,15,135,21,14,99,193,0,172,103,232,189,196,95,164,2,149,28,196,102,236,153,220,179,34,73,98,61,133,167,150,145,182,30,167,196,129,104,196,45,207'],
        expectedOutput: '0x646cd291,0x68cc0dda,0x0faac5a3,0x9e3cf69a'
      },
      {
        input: ['173,235,147,12,143,149,161,171,89,7,151,242,227,75,21,44,173,82,178,84,233,67,10,7,234,206,136,82,146,181,33,63,160,181,75,47,74,236,218,164,243,114,150,215,189,171,3,106,254,181,190,231,249,200,238,227,150,118,54,40,43,87,104,204'],
        expectedOutput: '0x451c777d,0xb5b23375,0x58627335,0xe0aa610b'
      },
      {
        input: ['12,179,251,87,160,214,251,147,72,145,106,5,61,110,111,59,35,45,34,28,245,16,0,139,134,54,179,177,141,27,125,154,207,121,241,111,79,236,2,151,125,109,156,186,219,11,245,254,56,23,27,45,39,27,184,173,81,107,95,222,135,220,120,86'],
        expectedOutput: '0xabbe6572,0x78f59870,0xe973be3b,0xf2dc8d25'
      },
      {
        input: ['85,105,197,164,85,199,59,211,52,215,141,15,226,131,14,26,154,41,71,194,68,255,111,149,107,206,115,242,171,236,72,0,85,13,165,171,212,224,126,9,184,11,24,154,142,38,181,41,79,252,235,147,252,90,40,103,41,156,89,212,136,161,212,221'],
        expectedOutput: '0x1c6b9af2,0x430aab35,0xc98a2d4d,0xc0054b93'
      },
      {
        input: ['174,121,136,130,90,6,139,18,18,164,172,160,202,97,201,26,94,180,173,90,15,214,193,56,114,26,12,250,187,224,215,105,90,96,235,180,102,119,198,120,27,114,25,229,212,226,255,50,151,173,140,166,131,77,222,245,103,234,239,34,202,198,139,36'],
        expectedOutput: '0x4dbac5a9,0xc19f1371,0x0a19ddde,0xa01fc9a7'
      },
      {
        input: ['38,118,216,141,237,158,5,8,17,30,238,229,1,237,23,152,154,163,62,29,240,28,18,87,6,1,121,208,200,4,245,238,122,205,123,104,108,129,112,125,159,94,98,160,76,121,56,230,28,118,4,12,146,22,99,152,24,220,105,224,224,94,206,90'],
        expectedOutput: '0x120a2763,0xcc475a32,0x36738636,0x32b95869'
      },
      {
        input: ['43,74,194,151,203,51,20,106,145,118,11,221,239,67,196,11,186,200,23,76,222,122,229,246,86,78,214,54,172,165,145,215,239,83,111,186,134,131,36,24,250,47,245,233,115,185,245,45,129,12,121,96,135,94,86,221,172,45,20,88,210,165,48,193'],
        expectedOutput: '0x2709a84a,0xcef9081c,0xfb335a08,0x886c603c'
      },
      {
        input: ['248,159,123,127,34,159,151,28,207,140,6,66,70,251,111,199,7,232,39,142,71,126,108,243,171,128,76,125,37,124,62,29,27,185,156,61,88,51,90,39,192,96,105,6,91,216,205,98,193,245,241,8,115,93,251,30,221,71,155,2,195,217,31,222'],
        expectedOutput: '0xb91c9ae2,0x9ee402fb,0x85a960e2,0x88978f60'
      },
      {
        input: ['146,188,28,234,239,118,18,175,214,123,181,49,84,131,147,21,120,132,29,235,225,24,9,190,96,164,192,35,125,224,2,15,156,30,249,139,148,11,59,106,135,240,155,219,115,46,240,235,179,13,214,148,37,223,83,133,131,19,169,0,243,171,15,143'],
        expectedOutput: '0x7c360f99,0x9b8a0670,0xf78b9713,0xdd39fc6b'
      },
      {
        input: ['201,9,27,93,20,86,199,155,70,98,118,186,144,102,165,67,115,124,216,153,91,43,30,223,62,199,223,50,114,239,193,59,248,220,152,12,50,95,168,121,193,30,51,82,133,216,149,248,84,109,145,176,152,176,143,215,119,110,9,234,93,202,37,85'],
        expectedOutput: '0x37ea01fc,0xd35c0c68,0x9557554a,0x11bd67c0'
      },
      {
        input: ['167,190,98,217,29,10,82,223,40,133,49,173,94,198,166,178,52,55,98,204,231,241,163,95,96,172,73,189,119,110,19,30,44,117,247,74,127,74,41,167,207,90,85,45,32,251,224,84,50,66,33,26,52,196,121,148,113,194,81,232,48,100,6,93'],
        expectedOutput: '0xd7224c55,0x977d5ded,0x1ddb89a2,0xa3b306fe'
      },
      {
        input: ['217,253,167,88,71,208,0,23,42,85,68,74,80,36,159,130,103,192,156,155,132,21,47,245,215,128,221,8,229,227,101,190,225,12,23,40,220,23,63,6,108,132,80,188,168,239,62,15,175,219,170,52,240,217,41,200,90,7,208,63,234,53,253,203'],
        expectedOutput: '0x5c1a8fe4,0x9d7ec356,0xadf185d9,0x1e327b29'
      },
      {
        input: ['65,20,244,29,43,51,35,151,183,115,83,96,99,146,111,18,109,26,70,93,243,112,37,77,119,245,140,97,42,138,45,107,158,33,136,202,84,171,97,12,31,181,108,130,71,219,148,180,245,219,17,233,75,55,54,194,44,195,35,87,77,80,194,235'],
        expectedOutput: '0xf8182d0f,0x644c740f,0xfdca0b13,0x4d50334f'
      },
      {
        input: ['113,75,181,198,246,23,210,21,204,62,151,19,25,44,199,15,7,216,248,82,15,46,20,60,241,55,147,62,136,85,42,249,160,223,191,151,246,145,172,194,207,68,213,233,112,156,248,119,117,240,201,132,30,221,192,16,20,83,78,156,169,120,150,73'],
        expectedOutput: '0x356d2bb1,0xa681691a,0x4a0bd50e,0xb9064100'
      },
      {
        input: ['88,85,224,78,231,141,17,182,209,230,159,65,131,151,184,248,135,129,124,166,94,61,182,114,144,4,15,57,125,165,131,213,250,99,35,225,240,52,152,193,27,55,2,158,207,186,150,86,59,18,252,153,79,178,12,224,183,27,25,52,192,156,9,186'],
        expectedOutput: '0x4b0c8895,0x09b020df,0xe993cfbb,0x1edfef03'
      },
      {
        input: ['0,44,156,240,97,52,178,124,107,180,26,58,111,176,145,170,194,141,68,18,64,80,242,247,107,11,43,43,168,52,229,168,96,129,152,193,181,74,61,33,255,87,91,110,7,236,24,202,122,92,220,186,172,206,177,23,217,220,66,129,16,40,41,112'],
        expectedOutput: '0xa057b4db,0xee4eb17a,0xdaf30a8c,0x406efbbb'
      },
      {
        input: ['169,194,50,95,12,111,128,11,199,219,121,206,200,146,152,66,238,116,252,155,66,173,178,28,137,245,157,153,29,199,9,198,137,59,37,149,171,165,161,114,129,26,64,73,172,217,139,155,77,135,54,144,52,232,172,189,221,73,86,250,16,95,193,153'],
        expectedOutput: '0x80d5a04c,0x0d395b16,0x292156ce,0x09cadcea'
      },
      {
        input: ['155,230,47,70,140,208,184,13,234,248,86,151,209,225,50,31,104,104,175,156,80,91,89,46,164,175,40,181,14,233,78,169,208,125,239,92,77,167,105,56,160,191,207,113,160,1,144,8,105,63,164,185,154,253,231,63,172,16,244,186,249,66,100,201'],
        expectedOutput: '0x3ab6fe5f,0xd4a93d02,0x77715b15,0x73102453'
      },
      {
        input: ['192,83,37,13,251,142,69,155,77,20,12,237,21,157,245,126,220,153,56,119,150,31,182,66,47,170,253,41,236,97,242,172,180,24,186,175,166,255,74,244,20,87,225,41,244,215,168,208,112,224,71,7,255,253,73,47,167,70,88,148,167,74,64,92'],
        expectedOutput: '0xfa5131c1,0x77c7f239,0x017dfcb9,0xe62ff7a2'
      },
      {
        input: ['98,250,11,9,250,86,253,14,173,222,55,161,181,223,113,38,191,185,45,191,182,118,238,94,189,70,242,100,144,50,192,243,45,204,252,39,34,249,53,207,215,108,112,141,76,225,179,11,154,224,202,81,86,184,175,19,254,161,120,143,211,56,130,0'],
        expectedOutput: '0x49ee73a8,0x43d8ae1c,0xd3ea1b28,0x512d6673'
      },
      {
        input: ['4,126,39,38,119,92,245,78,201,101,219,21,71,142,32,225,110,235,50,197,163,225,216,162,130,80,49,86,137,179,86,141,49,126,180,168,218,169,246,163,15,210,184,86,96,217,55,207,196,106,148,103,75,108,9,206,189,58,36,70,237,122,211,30'],
        expectedOutput: '0xd9ca8042,0x1183686c,0x193d8544,0xe6ad858f'
      },
      {
        input: ['248,135,198,211,49,189,118,64,143,47,150,239,8,205,190,204,55,82,51,131,191,61,81,124,119,117,194,101,239,149,131,232,29,74,187,78,7,49,142,150,96,36,133,104,241,68,52,41,150,104,172,85,165,253,209,28,114,147,129,97,41,5,73,70'],
        expectedOutput: '0x89a2c168,0x72870c05,0x3464f689,0x5e484f81'
      },
      {
        input: ['79,4,148,86,54,34,236,150,70,113,255,55,181,51,96,76,155,12,161,64,9,115,93,123,6,222,221,47,227,38,117,50,43,9,136,97,43,116,247,113,230,246,169,155,42,9,231,197,22,137,6,31,252,99,155,2,65,120,50,37,158,167,87,201'],
        expectedOutput: '0xca4c00b9,0xdc9fa063,0xed75f0b9,0x90117fad'
      },
      {
        input: ['177,224,42,220,84,34,78,58,24,247,214,66,0,189,8,22,70,14,54,66,113,209,69,178,73,119,215,231,30,47,177,207,15,219,172,99,253,250,158,22,241,116,88,241,49,96,8,120,110,62,186,223,15,255,146,88,118,105,63,149,152,240,100,167'],
        expectedOutput: '0x01f83d74,0x09aa28a6,0xddaa1591,0xb495d9a5'
      },
      {
        input: ['204,16,11,201,10,169,223,251,29,56,237,78,152,245,198,7,51,129,230,66,128,120,154,247,226,217,140,122,202,240,34,150,1,45,95,11,214,63,7,243,119,244,65,15,233,8,22,28,137,253,94,9,117,248,0,87,209,140,210,155,125,244,49,126'],
        expectedOutput: '0xe94f21ac,0xdae445c8,0x83f1b0d0,0x34231f05'
      },
      {
        input: ['33,145,137,247,208,144,234,71,132,43,86,109,51,109,137,188,106,231,198,223,223,198,55,177,83,9,76,208,253,126,78,30,15,215,21,223,104,255,38,236,42,124,90,94,233,227,26,83,203,224,51,170,167,106,91,250,115,168,202,112,38,24,142,53'],
        expectedOutput: '0x658d32c1,0x4d512be2,0x55707797,0x49345716'
      },
      {
        input: ['239,163,20,87,162,58,68,204,182,158,42,160,129,69,243,76,37,38,247,204,144,82,198,3,250,144,115,32,168,1,85,152,164,105,239,70,163,51,19,90,209,61,250,83,130,237,159,168,20,150,116,164,233,59,168,227,203,27,4,116,29,89,12,193'],
        expectedOutput: '0x5760bc9f,0xa05274d1,0x3964e8f2,0xfd8948d8'
      },
      {
        input: ['195,251,8,102,47,27,192,0,88,186,83,219,168,243,131,188,137,247,96,114,50,8,86,254,36,90,114,65,179,126,2,118,121,10,221,168,37,157,169,126,88,252,89,0,239,220,188,121,211,28,235,6,37,65,4,73,155,118,138,79,244,140,197,109'],
        expectedOutput: '0x564a9bb6,0x62cd85de,0xf14086fb,0x2e18c4e5'
      },
      {
        input: ['151,162,22,188,64,191,58,152,187,147,152,171,111,84,36,67,112,15,73,149,81,77,222,236,195,104,59,183,245,1,36,140,163,58,72,227,249,131,123,181,22,19,96,134,103,132,201,216,147,18,109,228,95,76,209,34,180,12,217,169,13,253,53,177'],
        expectedOutput: '0xea0a44f4,0x2ad6d610,0x82e4c089,0xc7faf598'
      },
      {
        input: ['56,126,148,49,1,16,230,23,35,70,157,139,202,102,99,94,120,208,66,215,28,19,249,209,32,210,122,45,208,176,222,8,46,115,57,47,131,32,70,166,102,228,49,49,74,148,143,195,101,209,154,129,229,148,82,5,102,205,50,54,125,17,62,171'],
        expectedOutput: '0x4c31b462,0x2affd552,0xafdcbc04,0xabf7645b'
      },
      {
        input: ['132,120,218,7,152,32,173,254,4,223,47,79,115,190,18,216,144,172,90,117,64,172,122,167,121,172,221,246,189,28,161,65,148,123,72,44,156,246,42,160,213,90,239,72,24,1,33,168,174,123,29,238,39,151,149,161,68,115,151,1,143,57,67,35'],
        expectedOutput: '0xa793571d,0xd5b06551,0x083a5d13,0x79693b55'
      },
      {
        input: ['180,139,79,80,129,121,241,86,211,224,159,236,226,192,148,144,59,178,126,98,73,20,3,141,135,155,143,22,212,210,57,136,93,136,217,223,1,202,53,213,170,212,193,140,148,85,28,207,7,155,50,81,175,53,222,54,208,109,76,164,63,133,45,157'],
        expectedOutput: '0xeea4228a,0x96a1cdd0,0x4f3134dc,0xecadb09c'
      },
      {
        input: ['13,6,124,14,208,177,227,122,134,164,7,26,250,35,234,1,190,28,82,109,81,49,163,34,158,239,198,222,116,243,123,129,249,247,144,201,168,115,68,46,24,75,73,18,110,51,19,45,79,102,154,160,151,62,194,53,45,137,19,162,124,142,35,118'],
        expectedOutput: '0x3f33cfec,0x0b735bd5,0xb0d22d66,0xb1b89ccb'
      },
      {
        input: ['133,179,63,46,39,131,92,63,206,165,81,61,216,100,106,39,202,4,200,97,66,138,151,112,19,170,18,144,57,53,6,190,233,69,236,16,201,73,79,151,238,160,212,199,4,62,238,207,67,182,48,133,65,199,245,84,114,7,228,171,61,234,105,38'],
        expectedOutput: '0x46b304f4,0xa8808317,0x88f746ca,0xd5bb9526'
      },
      {
        input: ['48,86,54,249,159,133,144,141,37,101,84,41,163,67,248,230,249,41,108,58,240,97,143,98,105,115,13,166,94,119,204,142,205,2,135,108,135,23,249,172,124,78,213,32,145,206,6,138,247,114,197,231,212,84,74,61,199,87,227,37,206,175,179,155'],
        expectedOutput: '0x52e60fcf,0x9f81e1cb,0x0b404dd5,0x798cd292'
      },
      {
        input: ['177,58,7,56,82,1,228,206,79,185,238,224,135,245,106,126,103,47,102,59,131,176,120,75,7,91,112,214,10,36,113,187,94,121,243,176,122,215,127,201,145,109,169,24,98,19,151,202,67,253,5,198,173,126,17,180,217,130,138,228,166,252,159,4'],
        expectedOutput: '0x26d0c5d6,0x933a7b3e,0x813a300f,0x1e8120e2'
      },
      {
        input: ['117,147,181,239,106,52,184,251,161,97,20,4,116,171,206,183,168,211,126,85,81,143,9,43,17,148,15,183,144,174,188,5,65,113,244,172,165,172,167,70,13,187,74,129,102,24,57,14,236,183,99,61,70,109,104,88,1,119,15,145,38,203,150,103'],
        expectedOutput: '0xeed4202a,0xba2ad6c9,0x14c5ec6f,0x8f79445c'
      },
      {
        input: ['60,138,19,225,54,187,40,67,118,114,196,221,139,253,235,119,180,79,180,251,188,29,83,189,148,98,78,186,46,228,34,106,110,53,76,164,240,116,231,103,230,171,68,113,169,47,232,93,126,157,88,58,186,171,247,78,14,69,9,60,41,43,166,151'],
        expectedOutput: '0xbba899d0,0x2c83820d,0xe3da02ca,0x1dc4c877'
      },
      {
        input: ['96,242,59,81,102,34,184,77,206,252,190,119,43,167,212,170,68,45,228,254,216,220,76,230,33,85,34,75,128,201,226,225,187,30,50,34,64,234,111,14,230,45,133,17,212,90,187,24,135,160,22,95,124,99,70,157,184,104,232,57,49,203,26,237'],
        expectedOutput: '0xcd3c1dad,0x8734903c,0xcb12a18d,0xe7e98e2d'
      },
      {
        input: ['233,76,15,41,54,126,56,28,171,189,45,128,23,233,152,158,137,175,254,5,18,68,162,202,172,139,3,222,86,29,203,63,105,218,104,159,88,160,187,3,94,233,131,117,210,28,20,91,203,18,96,221,86,2,167,2,141,171,224,227,200,171,34,50'],
        expectedOutput: '0xfe7d3c06,0x87432734,0x29ace3ef,0x5178765e'
      },
      {
        input: ['133,139,209,221,43,141,225,137,118,100,255,72,128,19,163,75,37,3,40,123,5,208,125,147,123,94,118,67,9,153,117,143,36,71,108,79,212,77,217,74,178,216,146,50,235,53,126,16,56,166,139,61,118,8,208,241,102,71,53,112,224,170,255,4'],
        expectedOutput: '0xe59324b8,0xdde807e9,0x622fdcc5,0x5c288537'
      },
      {
        input: ['241,107,83,197,185,44,15,107,4,161,157,239,214,27,255,14,194,138,76,56,147,28,42,249,99,95,105,67,9,104,71,251,212,155,192,141,199,208,248,204,113,149,187,72,177,187,86,115,69,162,171,216,191,213,210,34,52,59,102,62,164,173,57,120'],
        expectedOutput: '0x27dd7949,0x2a4cbd73,0xd7f03bd9,0x6a977625'
      },
      {
        input: ['72,249,5,16,201,253,220,59,146,151,131,67,82,217,182,152,124,98,112,59,55,66,93,108,126,195,170,34,113,227,154,185,220,159,201,166,156,165,225,46,61,100,114,143,61,40,39,185,138,152,244,194,218,82,46,88,21,216,122,134,187,20,64,151'],
        expectedOutput: '0xe4ee8414,0x697d4e5b,0xbc3d8a01,0xa0fc4926'
      },
      {
        input: ['179,9,61,79,175,30,126,236,130,240,123,192,24,163,121,163,59,110,101,21,192,147,110,213,107,232,92,38,253,156,189,176,165,251,0,84,25,126,64,156,110,188,92,134,95,213,41,154,67,142,175,3,33,29,217,140,6,53,178,3,209,112,179,118'],
        expectedOutput: '0x8700f23c,0x81cda05d,0x3d7e24ad,0xc720219c'
      },
      {
        input: ['107,179,203,132,49,11,32,159,199,124,38,38,82,79,192,149,222,112,153,255,141,114,140,147,167,62,150,120,174,74,238,25,253,185,158,47,197,190,206,140,59,244,179,141,68,115,34,34,227,187,33,113,45,173,4,212,236,155,76,154,229,59,180,226'],
        expectedOutput: '0xdccd9d83,0x80622339,0xfe6c167e,0xd89256c8'
      },
      {
        input: ['244,82,17,185,16,224,70,75,212,249,216,24,108,251,58,80,182,92,193,228,9,197,184,245,96,5,144,69,64,68,40,52,150,57,238,166,25,52,242,238,45,202,6,153,197,65,233,124,157,170,96,166,112,24,156,208,29,44,22,93,112,62,146,6'],
        expectedOutput: '0x6bcc09b1,0x71549afa,0x95a0af30,0xa23a208b'
      },
      {
        input: ['119,128,172,145,180,158,127,225,105,133,122,46,198,100,170,99,14,10,10,126,35,166,79,64,210,101,158,66,163,48,72,26,176,244,171,100,147,42,69,252,176,191,42,118,35,213,218,50,223,228,176,2,138,255,67,92,100,225,158,7,17,230,34,193'],
        expectedOutput: '0x64525285,0xd444a963,0x417a76dd,0x4f719898'
      },
      {
        input: ['218,205,37,109,248,106,105,168,41,148,30,77,105,248,127,72,220,47,75,102,47,142,194,147,111,96,155,128,70,189,65,33,138,102,142,130,208,248,42,249,140,73,70,245,65,197,61,30,245,136,132,36,22,71,183,133,167,82,5,238,15,70,15,154'],
        expectedOutput: '0xd58e7153,0xafc02992,0x4ff582b4,0xb8e01222'
      },
      {
        input: ['172,157,28,124,149,71,118,33,144,188,22,209,130,84,239,119,220,116,155,243,187,82,120,98,165,126,80,180,196,95,78,113,253,107,237,146,178,99,180,66,32,202,19,162,30,3,25,251,119,180,238,50,6,102,148,171,228,229,96,169,68,174,26,65'],
        expectedOutput: '0xb6cb65b8,0x30129c64,0x3f8b9872,0x668bb677'
      },
      {
        input: ['25,7,212,203,107,136,13,139,82,33,45,113,36,70,108,155,250,90,205,0,192,97,172,165,70,12,78,139,186,104,204,212,111,160,159,218,40,173,101,123,206,146,236,242,216,88,141,210,178,90,211,114,187,127,23,2,139,101,141,69,205,89,25,61'],
        expectedOutput: '0xdfdf2264,0x137fe25d,0x954f9369,0x97561b87'
      },
      {
        input: ['250,185,23,34,102,125,157,52,15,137,38,232,225,179,186,147,13,141,6,200,12,29,202,151,131,87,221,80,177,246,141,171,175,165,205,21,34,107,73,49,244,111,25,214,34,212,105,47,97,111,248,110,141,194,5,16,26,226,96,203,217,238,118,136'],
        expectedOutput: '0x00fb5069,0x57311677,0x707cfad7,0x00783811'
      },
      {
        input: ['147,67,158,181,174,231,230,163,87,0,121,121,212,226,169,53,82,161,163,223,99,169,239,125,139,79,72,100,61,190,237,208,2,139,133,176,114,108,83,201,108,204,67,64,175,236,117,1,141,25,224,240,194,207,110,77,30,182,178,92,117,159,44,119'],
        expectedOutput: '0xc133f387,0x1eec18c8,0x9567a28c,0x7ea81561'
      },
      {
        input: ['42,178,39,156,30,123,102,138,71,169,202,246,149,63,247,34,88,215,18,26,166,128,104,197,55,26,33,172,185,77,35,227,255,74,127,29,197,229,167,13,142,113,3,35,177,251,69,9,210,88,36,121,216,140,62,15,166,95,187,95,172,222,66,172'],
        expectedOutput: '0xe8544817,0xe19b6002,0xebb62f46,0xe3e88ec2'
      },
      {
        input: ['41,193,201,238,167,113,251,53,226,255,89,147,250,158,157,204,246,193,69,207,77,131,222,243,226,154,82,143,120,148,59,161,85,4,144,252,117,139,50,88,138,139,235,132,41,136,81,32,73,150,239,150,26,205,137,252,103,219,139,224,111,198,129,197'],
        expectedOutput: '0x20ddc37b,0xeef1bce5,0x387664fd,0x7afca2f0'
      },
      {
        input: ['203,17,193,64,157,243,152,39,126,132,172,168,12,253,200,86,147,183,236,173,132,118,170,236,81,53,204,193,252,77,134,199,95,71,7,252,59,160,35,185,36,207,97,48,204,41,134,96,224,115,13,101,233,183,81,58,237,29,251,233,106,129,176,201'],
        expectedOutput: '0x7685f700,0xe90b5c93,0x696e3381,0x153850c0'
      },
      {
        input: ['201,183,197,4,87,233,189,123,184,31,172,133,72,50,229,41,165,242,142,142,170,223,201,151,252,196,128,102,70,48,48,15,231,245,19,63,222,208,186,151,239,102,28,56,153,1,97,62,243,239,205,157,206,150,52,202,90,180,48,160,228,96,175,204'],
        expectedOutput: '0xafba8815,0x071e7da8,0x2f08b564,0x23edb628'
      },
      {
        input: ['86,194,11,52,147,197,203,130,44,231,186,197,232,27,3,220,10,208,121,216,102,174,162,193,98,211,97,71,51,17,19,137,211,30,190,102,227,137,233,15,113,163,212,89,191,216,53,201,168,175,162,15,93,68,208,191,23,49,6,75,66,25,212,22'],
        expectedOutput: '0x355fa543,0x7de47da6,0xd891c5aa,0x636470db'
      },
      {
        input: ['55,146,124,27,28,101,42,141,9,255,230,200,215,28,145,127,203,51,142,40,120,94,231,143,144,238,218,210,7,175,232,63,65,101,90,93,202,132,234,211,131,209,155,90,237,45,218,184,96,104,224,216,199,199,104,87,181,66,41,189,241,18,252,51'],
        expectedOutput: '0x08754661,0x4b2a67f2,0x175eb400,0x6ab37d93'
      },
      {
        input: ['119,86,144,65,218,123,21,94,76,176,184,57,221,146,241,62,251,209,22,194,152,126,25,78,193,66,11,178,84,7,229,203,93,118,13,55,241,34,149,61,210,78,118,176,224,103,238,219,56,4,157,208,131,182,30,68,249,41,246,77,48,220,25,141'],
        expectedOutput: '0x8422dc01,0xd30e5753,0xbf541ef9,0xfd88b602'
      },
      {
        input: ['82,38,197,67,72,90,128,26,168,246,202,137,93,184,100,149,189,2,101,64,184,132,132,177,173,122,255,222,86,24,107,168,62,48,235,134,139,107,160,51,97,107,188,190,35,33,83,224,35,185,32,219,61,164,141,234,31,140,200,117,164,52,30,226'],
        expectedOutput: '0xb7903aa7,0x7079f095,0x8da929f1,0x90645ef6'
      },
      {
        input: ['100,9,104,239,117,8,35,214,115,223,149,151,0,232,119,35,161,152,255,222,60,140,201,91,24,145,209,188,197,239,158,42,248,6,25,109,14,60,68,130,28,217,25,28,193,144,64,99,40,63,65,101,203,10,192,227,156,145,159,97,128,61,139,121'],
        expectedOutput: '0x04252ae3,0x11950895,0x7bfcd53a,0x5aa06579'
      },
      {
        input: ['67,165,230,81,225,42,211,253,3,236,26,197,125,90,40,165,153,105,10,100,116,203,71,16,92,230,113,221,35,253,86,102,162,60,183,131,103,139,129,106,119,155,47,244,245,87,154,142,193,164,242,53,111,57,69,204,31,182,169,66,179,255,168,85'],
        expectedOutput: '0xc6ebf7a1,0x75b9dcb0,0xb8d43bd5,0xfa6c3761'
      },
      {
        input: ['59,95,217,162,234,90,13,98,245,60,86,234,148,240,120,85,149,106,138,4,163,207,208,194,133,121,4,57,120,172,142,180,11,103,86,246,193,99,88,182,160,174,160,52,159,24,137,52,130,19,56,37,226,9,231,103,130,235,160,251,151,47,175,163'],
        expectedOutput: '0xd5cb20d5,0x6e17bdbf,0x07c4125b,0xbea6ea7b'
      },
      {
        input: ['150,5,153,88,105,241,14,9,159,175,61,62,199,198,114,74,217,171,111,187,180,87,34,54,66,195,49,218,242,224,125,136,230,22,224,79,7,239,88,166,158,149,229,101,91,87,175,52,2,31,239,182,118,17,237,184,212,30,146,198,255,15,79,229'],
        expectedOutput: '0x9f59a646,0x921503c8,0x0eda9932,0xbde20972'
      },
      {
        input: ['37,47,52,44,30,140,211,188,33,184,34,124,15,209,176,18,240,159,200,102,176,181,31,133,212,177,75,211,193,154,184,230,202,236,19,232,120,230,165,153,158,199,21,173,152,197,191,137,100,136,239,20,61,14,153,17,192,229,228,129,127,156,103,73'],
        expectedOutput: '0x92e96e5f,0xb125f86c,0x58fc26dd,0x6f7a8853'
      },
      {
        input: ['136,122,50,0,96,215,153,254,158,174,172,54,115,107,191,215,243,175,236,49,189,133,66,125,106,39,254,234,195,102,51,76,224,101,76,65,60,230,63,218,148,235,17,8,87,208,223,74,127,203,123,61,81,190,186,187,229,185,165,168,31,217,244,255'],
        expectedOutput: '0xe6d8e223,0x9908706c,0xd91d26e3,0xb5463fbf'
      },
      {
        input: ['62,65,64,123,39,128,85,187,107,102,195,194,55,163,13,182,110,136,243,191,70,174,123,43,103,32,212,134,249,200,133,56,9,198,179,48,70,8,236,177,111,175,116,166,82,129,92,193,9,80,128,80,254,251,123,101,28,79,235,21,24,112,77,33'],
        expectedOutput: '0xe1679243,0x48d345c8,0x4c7ad28c,0x5c255ef9'
      },
      {
        input: ['54,0,82,124,9,62,46,120,237,162,30,64,35,122,1,44,202,129,124,200,125,248,45,153,71,24,174,95,137,252,129,191,252,211,60,5,17,106,125,254,12,155,62,47,22,63,91,224,193,216,169,62,208,214,215,23,239,133,119,120,129,248,55,126'],
        expectedOutput: '0x656aac94,0x300494a5,0xb01ce381,0xb450683b'
      },
      {
        input: ['203,115,131,220,221,1,218,233,156,25,24,178,88,116,147,25,76,60,87,28,18,46,51,1,180,170,121,53,162,177,179,109,36,55,73,2,56,36,235,212,61,4,135,149,120,26,175,196,86,6,224,104,53,19,106,233,190,227,30,96,148,210,206,185'],
        expectedOutput: '0x3218cd54,0x0a1efd0f,0xd91caf26,0xaf336f2f'
      },
      {
        input: ['9,23,187,65,59,166,21,120,170,156,14,34,182,189,230,12,195,198,117,248,218,223,225,152,194,0,248,87,210,198,16,219,222,203,28,25,113,49,146,28,206,160,62,132,93,37,145,32,235,6,25,197,229,250,93,167,250,86,254,204,28,14,167,250'],
        expectedOutput: '0xc00c92c3,0xe648e12b,0xdc3fc2ae,0x6bb9320e'
      },
      {
        input: ['217,195,20,75,245,166,103,195,70,165,71,163,202,216,195,182,222,220,123,195,215,217,107,209,47,105,158,75,120,69,70,81,9,90,156,254,0,3,193,70,169,8,233,115,225,172,41,191,137,165,131,96,126,238,49,173,87,207,248,207,21,62,33,30'],
        expectedOutput: '0x631f9f18,0x6a95a835,0xa2e369d9,0x983bca3a'
      },
      {
        input: ['152,189,28,152,193,221,222,106,229,199,221,198,116,7,134,253,172,9,93,42,247,142,215,78,94,207,30,115,14,63,145,166,252,173,63,189,138,29,39,111,229,5,54,89,12,188,86,184,197,179,226,188,65,185,10,159,136,40,18,150,103,163,61,100'],
        expectedOutput: '0x6c09709f,0x7024db4c,0x294d42cc,0xea6d2b32'
      },
      {
        input: ['80,124,33,218,153,73,74,126,78,128,215,90,60,45,18,1,224,244,189,34,173,199,193,53,240,212,204,87,119,9,187,200,133,221,162,30,38,236,157,116,108,116,206,168,162,224,169,130,212,102,164,129,46,102,182,30,58,130,117,177,139,49,121,16'],
        expectedOutput: '0xa57a6394,0x484a2fb5,0x45e20630,0xf044d13e'
      },
      {
        input: ['14,28,47,52,8,204,168,117,64,118,29,226,86,199,101,42,45,9,171,91,111,97,121,169,228,239,91,111,32,212,128,46,240,175,98,249,123,10,110,187,128,139,158,214,82,3,0,128,12,171,219,124,12,85,37,240,68,128,96,100,85,224,146,69'],
        expectedOutput: '0xb3216e96,0x41ed3bf5,0xf6cf9f04,0x7ea5452d'
      },
      {
        input: ['143,244,62,10,254,172,197,126,56,99,84,138,102,84,10,115,255,230,239,11,59,20,252,127,149,92,227,234,60,117,47,203,105,110,213,103,26,154,229,82,254,57,221,100,141,231,215,140,205,198,151,8,219,147,135,112,239,106,90,43,223,137,246,72'],
        expectedOutput: '0x77842afa,0x6932fcf6,0xfcfad7c6,0x151e5386'
      },
      {
        input: ['247,203,175,18,102,148,100,100,205,65,200,90,41,160,230,246,102,126,255,65,17,134,177,1,241,11,44,208,149,35,25,140,238,200,158,84,93,3,184,42,68,129,133,109,33,107,100,135,233,99,201,251,233,122,252,218,134,40,171,27,75,196,167,58'],
        expectedOutput: '0x09d64f4c,0x9f039058,0x2e3169c5,0x1119b1a6'
      },
      {
        input: ['140,70,142,233,73,71,20,141,200,153,251,233,4,95,112,238,194,57,233,171,180,229,134,58,13,49,85,89,245,252,147,129,66,33,107,139,104,127,25,48,24,20,25,28,115,138,10,53,195,243,224,119,216,102,177,230,151,6,63,140,3,210,14,69'],
        expectedOutput: '0x8ee2c272,0xf481937e,0x37245e90,0x746f5397'
      },
      {
        input: ['243,121,209,92,248,234,140,16,254,166,44,113,48,55,166,243,42,134,107,3,237,28,233,132,35,40,17,38,250,31,107,237,152,60,73,144,38,214,160,36,124,204,149,172,3,59,159,46,194,10,49,175,39,26,51,74,66,68,112,60,99,219,41,251'],
        expectedOutput: '0x6b1ae504,0xa0d218a7,0x8edbd3cb,0x73f58345'
      },
      {
        input: ['24,115,139,62,73,43,99,197,248,248,113,251,52,16,41,246,27,90,165,66,116,216,140,182,29,252,242,128,215,28,124,239,143,7,46,216,51,145,157,43,137,14,38,189,30,80,179,57,170,88,123,31,49,7,213,78,3,200,206,219,228,74,202,115'],
        expectedOutput: '0xa94dc0e3,0xecc5da08,0x1e4e8a52,0x6e99da63'
      },
      {
        input: ['82,248,75,133,137,232,176,19,246,214,208,20,38,132,78,209,220,201,240,13,209,197,91,212,141,42,175,113,116,122,228,198,114,47,75,252,23,251,15,13,210,223,34,248,99,112,201,64,57,185,77,10,127,169,223,12,211,142,126,71,8,98,14,123'],
        expectedOutput: '0xe2779826,0x6eb6d63c,0xef7f39b5,0x69d42abe'
      },
      {
        input: ['146,89,119,169,85,134,183,39,101,217,31,201,73,233,9,130,162,86,141,33,255,108,46,210,250,172,26,3,14,40,126,160,129,245,74,214,123,1,253,224,218,29,169,35,6,178,165,168,9,50,202,8,158,248,219,153,164,245,156,178,29,26,83,158'],
        expectedOutput: '0x23bee04c,0x86aba9ad,0xade333a3,0xa78216b5'
      },
      {
        input: ['15,157,117,138,158,114,106,120,143,20,155,149,198,64,62,207,115,8,216,17,0,179,170,164,168,70,86,197,96,169,99,111,70,216,249,228,75,100,92,218,120,247,112,62,56,174,14,171,182,230,188,182,153,103,90,65,173,176,6,14,90,105,125,160'],
        expectedOutput: '0x1a083a69,0x51799f11,0x2a19fa3c,0x00dba80a'
      },
      {
        input: ['66,119,133,141,219,225,103,83,217,215,145,17,133,159,188,59,133,120,241,30,223,75,95,141,252,101,155,86,207,24,246,17,143,123,158,106,93,5,189,54,221,79,71,98,238,3,158,116,123,143,146,91,219,242,232,215,87,131,45,38,155,35,55,43'],
        expectedOutput: '0xba412289,0x7c36a196,0x8f368870,0xbd3dffa0'
      },
      {
        input: ['159,213,149,252,219,83,50,184,162,121,26,144,124,184,4,247,72,151,82,35,137,58,250,224,189,39,7,89,74,62,132,233,20,25,229,239,108,23,167,14,144,193,159,12,122,163,4,194,58,86,229,195,145,223,164,78,6,171,167,80,233,43,58,253'],
        expectedOutput: '0x30760881,0xfa0161d0,0xd40f83ed,0x044b2703'
      },
      {
        input: ['69,31,236,177,55,147,192,199,85,95,212,207,2,216,145,61,46,118,0,191,85,164,14,91,79,181,171,57,225,229,54,38,5,35,215,60,182,151,3,11,246,215,218,249,175,107,54,222,225,54,157,54,219,171,145,42,97,61,99,66,34,154,104,39'],
        expectedOutput: '0x2e891a26,0x24f450ff,0x4a226533,0x7a7734aa'
      },
      {
        input: ['189,63,99,115,215,103,127,205,62,89,198,238,197,252,204,166,51,105,221,14,21,110,56,118,171,156,184,206,54,32,245,243,95,89,102,54,192,229,4,254,63,202,236,4,199,184,170,250,34,135,8,55,246,64,173,161,220,101,111,18,133,101,5,228'],
        expectedOutput: '0xdac962e8,0x43430c0e,0x8230f31d,0x42405f6c'
      },
      {
        input: ['190,108,27,126,81,31,124,144,233,105,148,176,33,63,170,67,198,178,122,188,243,39,94,207,140,205,226,17,50,231,246,240,83,17,110,165,48,235,53,25,84,202,202,117,9,116,185,207,39,51,140,26,91,234,233,231,183,203,249,234,179,239,218,6'],
        expectedOutput: '0xb9bd0857,0x3285f0a8,0x0833f0ad,0x40f6ae9b'
      },
      {
        input: ['0,73,171,48,52,225,73,136,171,19,253,180,136,182,131,175,234,15,201,69,249,178,44,177,126,37,155,49,20,117,55,20,190,227,68,242,196,142,122,111,161,120,35,41,46,166,216,24,182,161,93,175,84,138,96,210,175,251,3,196,113,58,216,47'],
        expectedOutput: '0x3704ea84,0x52aaf686,0xa87178e9,0xdb41918e'
      },
      {
        input: ['29,29,34,225,171,156,80,76,20,115,118,67,26,78,91,208,240,185,127,68,67,224,22,242,219,25,182,76,83,143,124,113,172,158,82,87,58,163,163,79,22,25,146,48,104,237,0,88,166,128,156,233,96,178,220,59,203,146,136,30,33,4,143,205'],
        expectedOutput: '0xaf1536ea,0x3b38d022,0x83f9db19,0x87803c65'
      },
      {
        input: ['162,226,36,220,133,200,43,155,225,189,204,73,171,204,161,81,76,61,59,172,239,23,232,186,169,112,217,203,116,104,152,22,74,189,242,207,133,30,107,102,219,55,176,134,3,81,216,80,143,19,252,126,42,228,57,211,84,18,158,200,122,55,222,197'],
        expectedOutput: '0x05a59036,0x7b8b16b3,0x145f5832,0xdf1163b0'
      },
      {
        input: ['244,209,148,121,239,255,223,202,54,143,81,58,225,41,138,112,60,134,238,102,107,39,57,191,57,216,136,180,15,102,121,3,55,13,124,38,13,91,241,67,235,66,125,204,107,7,60,167,142,42,13,249,82,70,184,139,30,64,63,45,167,184,48,222'],
        expectedOutput: '0xebe6980c,0x893135a0,0x366a54d3,0x987c8be1'
      },
      {
        input: ['198,172,5,211,8,246,22,243,56,148,191,163,155,251,74,41,37,87,34,119,157,219,3,188,27,66,233,194,251,26,161,193,198,166,148,206,156,170,193,212,62,128,119,218,123,193,3,161,24,38,24,181,1,27,113,28,94,91,223,89,117,128,26,59'],
        expectedOutput: '0x82ed4c26,0x640ab3bc,0x105b897f,0x12c5d8d8'
      },
      {
        input: ['38,174,10,194,88,203,150,151,76,13,113,199,206,116,104,230,154,129,155,155,156,13,184,250,104,151,83,221,23,109,24,61,27,34,255,116,238,149,11,58,162,124,1,112,240,106,86,139,235,241,38,135,254,222,130,102,117,213,67,140,67,92,201,94'],
        expectedOutput: '0x31065c31,0x9f9345af,0xdd56748b,0x5ceaa5a8'
      },
      {
        input: ['126,200,210,108,93,221,166,255,89,168,111,74,18,197,213,253,183,251,132,181,218,6,28,79,220,95,220,31,187,165,125,58,110,80,166,203,45,77,203,135,245,58,209,7,0,166,4,183,161,136,108,123,143,136,203,107,232,167,138,163,76,7,221,186'],
        expectedOutput: '0xa68aba59,0x3f4695fe,0xc58deddc,0xfa2ced9c'
      },
      {
        input: ['87,132,134,133,209,81,12,198,139,221,205,139,131,209,66,36,89,175,160,232,55,107,83,31,18,221,195,94,229,160,25,60,36,159,193,245,240,205,187,123,170,136,7,45,89,73,82,179,248,242,155,48,93,239,79,111,204,18,205,177,179,230,238,215'],
        expectedOutput: '0x887e07d4,0x81fc4c42,0x1ccca04b,0x0d05dd5f'
      },
      {
        input: ['133,175,205,117,125,136,241,39,17,248,85,106,65,167,29,58,153,185,106,246,168,185,101,116,204,50,38,127,25,20,86,158,195,35,20,64,172,5,104,189,253,189,39,62,100,69,120,253,254,226,243,166,156,88,26,104,138,64,231,163,84,61,66,24'],
        expectedOutput: '0x2598c3b7,0x9c8bc1d4,0xb0a910d9,0x8fdd9135'
      },
      {
        input: ['97,86,88,13,91,192,202,88,125,241,150,225,54,15,222,52,241,209,218,141,41,245,245,180,53,220,87,138,26,153,162,123,239,250,136,74,187,82,162,56,67,57,26,122,72,248,174,57,202,137,199,243,126,188,167,179,153,255,61,179,152,223,46,136'],
        expectedOutput: '0xe59347e6,0x664137a0,0xe3df0a6c,0x541b9df8'
      },
      {
        input: ['218,182,210,149,8,117,205,75,174,231,197,246,224,116,47,170,253,246,157,123,179,69,46,76,68,108,255,220,75,45,100,37,227,55,186,235,172,136,54,90,111,252,80,79,112,127,249,109,118,151,232,41,220,22,117,32,130,116,252,206,161,97,243,132'],
        expectedOutput: '0x19622032,0xc12b4cc6,0x6f965bd4,0x49574684'
      },
      {
        input: ['152,174,111,68,54,165,158,165,161,238,245,17,109,238,126,227,133,102,12,97,125,129,129,255,245,126,205,150,223,193,26,119,111,137,187,165,47,89,74,208,71,63,226,180,46,96,152,179,199,164,21,68,38,150,67,27,20,17,178,243,210,204,106,65'],
        expectedOutput: '0xd331bdc3,0x245405c5,0x078dd96c,0x4d8bf693'
      },
      {
        input: ['86,37,230,133,126,48,85,197,112,55,122,158,152,18,81,95,182,102,163,220,253,230,248,17,247,170,5,201,118,111,10,204,149,240,81,19,33,167,217,145,222,83,47,118,101,128,213,27,231,120,248,228,95,240,245,86,154,250,32,16,106,42,221,255'],
        expectedOutput: '0xcc4c1517,0x46e7fd6f,0x3fe08a55,0x1aea2660'
      },
      {
        input: ['27,46,18,60,213,235,205,180,62,252,42,163,124,0,191,99,120,183,71,215,167,61,46,65,55,78,81,161,120,46,160,147,93,179,207,50,158,156,230,221,152,17,128,21,17,63,120,137,246,192,97,157,253,143,222,52,221,48,214,85,94,118,233,187'],
        expectedOutput: '0x8aee9e28,0xfa37f58d,0xcb55e47c,0x6962965d'
      },
      {
        input: ['41,184,238,200,85,212,165,237,229,37,2,246,101,123,128,91,59,225,249,56,112,215,108,77,7,66,162,102,185,139,33,226,68,15,170,153,228,79,134,201,117,137,192,218,4,64,53,63,33,46,119,145,6,227,222,13,38,128,115,223,12,149,193,80'],
        expectedOutput: '0xc37831ba,0xe3aa4d4d,0x90f46b79,0xc3e2cb3d'
      },
      {
        input: ['164,108,233,136,187,111,82,48,248,18,10,252,82,64,59,115,110,178,4,116,150,226,130,188,98,245,155,110,138,92,190,47,200,167,183,132,23,9,180,15,27,191,12,109,255,71,224,109,250,228,226,144,198,100,76,41,89,231,151,228,67,86,19,12'],
        expectedOutput: '0xbf769d0b,0xd0a2e35a,0xea6b7271,0x6ea70b34'
      },
      {
        input: ['253,202,144,20,212,68,36,239,3,48,93,2,119,61,112,113,34,82,1,232,182,77,17,15,52,169,243,120,255,6,132,252,209,20,17,165,88,53,148,92,101,241,94,220,47,206,78,81,32,79,57,214,157,75,230,209,244,217,73,243,224,205,239,177'],
        expectedOutput: '0x5a69d923,0xdb5dc4af,0xa504b1ee,0x451d1a3a'
      },
      {
        input: ['225,0,86,58,53,234,150,154,220,244,119,11,195,197,92,227,20,149,186,177,224,160,131,212,121,204,199,89,154,183,10,123,183,96,181,237,75,75,135,39,64,254,50,3,195,142,230,216,35,160,137,4,64,12,216,186,217,160,19,115,87,30,238,14'],
        expectedOutput: '0x91d56fc3,0x8f6ebca4,0xbebbfa82,0xcd2db4c8'
      },
      {
        input: ['126,164,251,201,239,131,240,47,129,34,50,69,176,25,29,212,185,166,216,250,179,176,180,140,80,199,255,167,229,237,182,100,145,177,45,129,52,30,176,182,64,227,251,241,252,24,197,181,190,157,175,113,77,99,253,158,43,252,69,16,234,251,116,123'],
        expectedOutput: '0x6af28009,0x50a4f997,0xc6b499c5,0x1f97958d'
      },
      {
        input: ['173,162,252,225,192,173,151,0,144,146,241,140,170,182,65,105,83,241,218,161,84,216,63,127,212,132,144,190,128,4,58,45,166,54,14,102,227,166,103,115,56,88,255,227,15,65,76,98,50,38,3,134,254,66,6,211,199,150,145,71,154,203,116,65'],
        expectedOutput: '0xa67e984e,0xf30c09be,0xfcf81ba1,0x731d0d50'
      },
      {
        input: ['2,130,167,229,40,14,89,97,103,88,68,118,153,144,216,203,182,220,82,181,30,88,136,229,238,25,44,136,229,160,201,231,35,113,204,75,127,37,172,230,126,240,92,23,128,53,227,55,17,53,236,47,141,116,21,123,141,65,3,114,226,205,89,5'],
        expectedOutput: '0x46bd5288,0x938ee23d,0x8db988c9,0x6d7ddf0b'
      },
      {
        input: ['62,38,80,189,75,253,164,201,237,0,225,110,53,196,165,70,249,145,118,134,5,139,1,146,204,4,5,174,209,94,179,15,132,4,205,208,1,113,153,238,113,122,92,167,62,1,237,55,146,99,189,151,238,190,42,187,195,47,105,148,141,29,164,18'],
        expectedOutput: '0x4869dd6d,0x4ddcdecc,0x6443b3b6,0x464d57be'
      },
      {
        input: ['33,113,226,34,226,123,16,83,246,109,250,52,110,232,108,1,75,41,152,58,232,194,245,171,241,94,63,127,123,227,145,156,84,115,190,54,238,207,138,228,60,132,25,170,108,133,171,184,174,68,242,150,6,231,65,248,69,129,119,193,100,8,93,185'],
        expectedOutput: '0xdef45a3c,0xff9734e7,0x8844a8f1,0x4ed29a98'
      },
      {
        input: ['123,28,239,105,235,121,78,39,254,103,209,106,236,125,34,154,193,20,49,199,251,114,191,65,243,54,2,88,62,95,17,185,123,0,35,102,122,113,141,120,216,95,226,196,220,5,94,157,25,143,100,21,2,36,86,245,90,88,77,153,183,94,82,51'],
        expectedOutput: '0x6404cf43,0x9e12f144,0x69a90ab1,0xba3f256d'
      },
      {
        input: ['95,117,153,217,230,39,81,190,134,51,130,98,56,225,255,82,112,99,103,114,135,189,104,226,21,181,123,204,20,205,255,115,67,153,76,41,192,157,232,70,208,106,168,9,75,167,91,188,10,194,46,146,127,150,116,148,76,239,96,96,188,96,211,255'],
        expectedOutput: '0x622f43f3,0xf46ec8f0,0xe856a2ab,0xb099a9b2'
      },
      {
        input: ['249,31,41,185,188,17,255,140,123,167,149,199,78,240,131,88,178,177,234,49,72,94,197,148,77,38,244,10,134,199,9,127,230,50,56,162,67,55,46,191,222,196,134,44,180,9,132,103,186,111,152,2,205,94,150,27,132,138,37,10,81,46,137,55'],
        expectedOutput: '0xebeea452,0x2d581d5b,0x73435b43,0x454ae0b0'
      },
      {
        input: ['97,193,217,164,248,8,99,214,204,233,2,128,242,134,231,173,245,128,175,195,222,70,222,98,208,3,108,34,49,245,89,146,182,51,55,174,59,154,132,7,132,134,135,118,12,111,35,2,239,211,197,205,25,163,47,233,166,155,11,215,144,101,106,70'],
        expectedOutput: '0xeaa8d1de,0xf54908a3,0x22292eb9,0xca1edc77'
      },
      {
        input: ['152,161,244,211,59,120,218,191,254,97,54,10,208,89,12,191,44,209,140,69,116,187,47,26,86,58,242,230,159,92,44,55,253,32,10,56,152,228,248,150,70,46,161,22,135,173,214,180,127,98,249,243,30,40,14,116,99,0,91,2,92,135,58,89'],
        expectedOutput: '0x950b16aa,0xc578ecdb,0x418a4999,0x919f8782'
      },
      {
        input: ['168,68,145,64,41,137,215,111,183,120,133,63,37,91,243,164,190,236,152,220,21,166,80,120,166,171,122,2,51,180,91,219,249,236,27,34,118,242,145,45,106,22,108,144,114,95,52,48,76,204,12,97,114,92,217,24,8,83,26,59,8,117,22,1'],
        expectedOutput: '0x5bb2bbb4,0x5bf35b54,0x961da6b3,0x8bbe4d19'
      },
      {
        input: ['98,49,35,216,36,180,5,142,202,114,30,60,209,83,108,29,31,120,126,146,213,87,170,221,171,197,24,179,58,46,180,156,95,215,116,131,139,122,18,85,236,48,146,189,131,254,219,163,119,89,53,76,177,223,41,92,164,65,15,223,111,195,123,206'],
        expectedOutput: '0xb1cac046,0xf160f1d0,0x25184213,0xafabd6e1'
      },
      {
        input: ['154,240,82,37,106,100,122,86,148,12,19,24,11,238,187,130,72,240,206,249,207,247,85,116,56,100,83,167,39,206,117,193,190,199,230,40,43,96,126,192,109,146,216,120,128,147,250,200,131,200,193,82,191,22,198,247,122,25,158,161,232,19,98,166'],
        expectedOutput: '0x5ffd45ee,0x49f2e5ab,0x8708db0d,0xd63a6dd8'
      },
      {
        input: ['219,72,207,6,169,77,198,22,223,158,142,96,49,136,40,180,80,234,7,15,0,205,6,123,231,164,28,207,183,127,117,146,199,68,153,112,146,95,134,113,254,20,209,47,156,250,228,236,228,235,251,228,184,1,95,159,165,124,110,93,251,228,239,194'],
        expectedOutput: '0xa09bceeb,0xa8fa20ea,0x8da778b0,0x93f527b1'
      },
      {
        input: ['40,136,51,186,232,185,44,230,206,253,21,106,247,249,87,219,228,82,192,157,84,31,60,249,155,171,86,150,143,70,89,183,206,140,114,182,69,158,156,19,155,178,126,147,171,213,110,144,39,46,45,123,78,105,117,233,20,203,128,163,17,217,91,224'],
        expectedOutput: '0xe6d2ffc6,0xfe8f9f1f,0xbf694bab,0xb40eed62'
      },
      {
        input: ['101,205,150,170,107,51,190,6,229,60,153,144,17,8,32,56,54,77,180,132,183,41,110,203,244,238,111,6,199,202,230,44,151,124,214,2,175,148,8,148,208,162,37,225,170,69,26,224,147,206,101,74,247,211,21,235,193,132,241,136,78,215,180,229'],
        expectedOutput: '0xc616ea39,0xf16833f0,0x8b082f83,0x9c372c1f'
      },
      {
        input: ['84,138,231,3,31,240,152,239,146,189,209,60,2,235,28,149,185,129,223,176,84,245,155,21,121,141,157,200,100,81,173,184,220,149,188,251,133,84,234,23,17,187,83,19,166,111,169,95,241,136,15,69,125,171,91,247,56,248,191,156,74,108,85,38'],
        expectedOutput: '0xd372d4c4,0x29490862,0x2fe30312,0xbcab36a7'
      },
      {
        input: ['1,17,33,134,101,11,157,118,199,240,137,109,96,50,205,81,187,220,150,56,135,241,47,191,234,238,92,52,91,177,90,92,194,123,227,39,134,128,157,77,113,38,187,209,89,136,34,20,100,184,76,236,170,124,171,148,106,7,200,197,184,34,34,122'],
        expectedOutput: '0xb824b1d4,0xd5e1f425,0x701da6cf,0x69d868d8'
      },
      {
        input: ['157,5,161,35,133,62,113,246,101,44,199,190,180,233,210,24,162,30,4,76,154,176,224,5,183,168,202,112,202,236,234,103,241,140,138,119,202,251,109,47,39,53,237,219,30,191,244,192,222,248,12,120,168,236,125,96,148,72,208,94,52,186,197,38'],
        expectedOutput: '0x50972378,0x03a0896f,0xcf88d0f3,0x32b587f2'
      },
      {
        input: ['70,80,157,17,75,10,64,115,63,46,78,94,237,66,30,203,59,43,68,227,23,193,67,172,9,19,10,62,206,208,100,20,32,1,37,107,11,102,222,75,148,45,169,129,111,199,77,170,242,145,142,10,82,209,182,92,229,192,154,179,144,254,199,176'],
        expectedOutput: '0x7a783564,0x0e481cbe,0x338808f5,0xe9683f32'
      },
      {
        input: ['255,237,28,10,83,250,85,231,39,254,104,151,198,181,65,184,70,207,194,153,161,120,245,134,57,143,57,201,141,0,122,140,237,150,150,64,144,236,39,184,234,144,79,176,69,144,105,140,96,43,37,1,164,26,135,221,169,192,166,54,192,32,194,174'],
        expectedOutput: '0x3540eff5,0x7fe8036a,0x04c32228,0x90c37c86'
      },
      {
        input: ['182,88,238,71,68,22,255,47,166,78,223,235,222,72,119,62,116,156,63,24,182,198,245,95,134,155,149,71,188,87,245,114,176,227,185,244,249,184,35,159,6,3,139,229,75,2,35,191,159,99,215,85,41,204,181,176,104,74,247,36,162,236,150,82'],
        expectedOutput: '0x620d7945,0x66bba012,0x79b20b7b,0x596e184e'
      },
      {
        input: ['207,80,70,201,8,106,104,15,109,243,244,184,246,23,120,149,122,79,234,164,28,159,84,132,234,75,168,140,55,62,222,6,142,36,207,151,142,56,166,251,43,154,180,33,177,44,182,44,123,161,208,151,64,36,27,42,111,195,182,166,2,148,172,144'],
        expectedOutput: '0xa2479413,0xfd483cf2,0xe0c25e7b,0xbdec2b8c'
      },
      {
        input: ['185,124,39,71,180,205,67,223,103,247,1,25,35,183,69,158,88,21,54,153,57,81,195,168,21,122,78,23,14,250,167,199,118,207,15,42,156,82,10,4,73,11,29,108,194,98,10,27,119,64,180,176,146,119,88,167,241,166,190,0,160,101,199,23'],
        expectedOutput: '0x00f3d5cd,0xa4753957,0xbd163013,0xa04009a8'
      },
      {
        input: ['52,214,65,209,40,75,213,113,86,242,221,25,84,232,52,203,40,232,123,186,95,211,97,81,121,31,81,25,133,24,48,185,239,114,138,23,189,95,137,20,81,102,45,165,78,97,112,119,73,235,49,168,190,147,249,55,178,74,81,55,99,129,241,82'],
        expectedOutput: '0x1edb2a64,0xe3d38901,0x38fd289b,0xe7d847b5'
      },
      {
        input: ['243,123,105,177,219,242,197,44,89,242,210,167,83,66,30,156,46,80,68,236,227,62,36,149,136,117,205,235,246,190,61,234,57,167,155,20,153,96,65,242,82,19,154,165,85,184,65,131,8,133,112,235,195,148,129,76,9,78,55,255,12,117,233,69'],
        expectedOutput: '0x046e581f,0xf42bd5fd,0xf110491d,0xbf3dfafe'
      },
      {
        input: ['28,132,90,181,228,155,168,54,174,66,219,3,250,28,135,3,162,247,238,101,139,111,177,148,189,233,147,201,94,125,15,122,1,105,47,230,4,215,28,178,25,248,181,20,20,60,23,182,51,5,28,190,117,205,82,50,182,230,252,20,99,11,142,100'],
        expectedOutput: '0x6b3502f9,0x3d09e58e,0xf0f17a0f,0x8e37317d'
      },
      {
        input: ['116,190,74,120,149,103,42,175,95,223,195,115,28,218,42,79,223,70,14,84,19,96,135,202,70,131,222,169,142,109,14,2,43,88,122,192,191,164,111,30,131,50,146,159,12,188,239,236,2,253,64,21,93,199,223,164,74,190,77,216,43,91,218,86'],
        expectedOutput: '0x330f0981,0x87fb6cb2,0x8cac1fc3,0xa97a0c5f'
      },
      {
        input: ['180,84,22,115,248,134,146,124,184,36,27,197,224,10,177,226,7,241,247,101,185,215,9,3,149,86,220,192,178,182,22,102,11,44,217,3,178,107,127,107,143,155,48,111,165,225,81,173,210,73,18,139,32,27,143,181,113,107,117,35,33,139,137,44'],
        expectedOutput: '0xeea37de7,0xd65ae66b,0x19b4a7cc,0x170b4f78'
      },
      {
        input: ['183,99,48,106,206,175,213,94,74,5,205,240,230,31,157,184,104,175,68,136,202,211,61,59,62,178,95,95,61,232,140,244,75,188,94,26,107,51,120,182,56,69,166,30,100,67,215,204,242,27,84,188,238,145,247,44,67,86,139,128,63,23,117,138'],
        expectedOutput: '0x61866054,0x42aae064,0x5029b2bf,0xd7a31ded'
      },
      {
        input: ['211,211,164,63,7,28,245,63,98,155,94,198,222,53,147,208,80,231,140,62,121,131,106,188,218,245,61,25,13,178,163,224,133,72,31,140,100,20,204,198,175,42,141,141,95,32,93,175,7,233,237,128,109,87,61,71,76,122,96,89,44,3,58,177'],
        expectedOutput: '0xd0260f6e,0x72ec2c38,0x462821fe,0x9ac0546a'
      },
      {
        input: ['75,89,62,176,110,10,118,29,52,3,171,147,35,8,66,43,242,47,171,95,134,232,166,210,98,6,44,142,9,102,64,85,191,126,5,45,136,123,75,188,127,246,79,162,254,145,205,240,192,121,79,70,97,245,24,196,251,68,82,5,170,146,90,106'],
        expectedOutput: '0x1e38aa34,0xebc9f11d,0x384ac6ca,0xfdf7c21b'
      },
      {
        input: ['16,95,151,152,218,226,84,89,216,163,252,215,52,201,199,244,66,23,58,164,12,83,104,8,151,186,13,66,77,103,172,93,198,67,246,160,38,74,250,254,238,246,213,34,191,157,23,2,180,81,166,192,164,14,200,60,200,213,126,21,60,42,115,2'],
        expectedOutput: '0xc52c6056,0xfffe713c,0xc4bf938b,0x82eb1d18'
      },
      {
        input: ['109,105,163,147,179,157,146,161,147,103,196,82,4,219,84,184,44,250,121,209,8,65,13,209,23,139,230,83,181,89,86,34,194,249,182,118,150,72,23,41,175,219,123,180,182,208,108,227,202,229,180,211,39,193,164,62,76,138,145,1,228,231,35,166'],
        expectedOutput: '0x4945c2ba,0x7e568cad,0x7facc4ed,0x03bb5602'
      },
      {
        input: ['224,217,28,118,33,52,159,209,15,27,133,198,235,241,169,181,215,93,136,254,30,44,60,106,183,205,107,155,181,142,65,149,104,94,12,137,146,171,90,161,198,223,103,177,209,16,103,168,109,239,166,139,28,226,245,211,175,96,110,100,239,175,250,87'],
        expectedOutput: '0x7ec5fc9b,0xbf8eaa5c,0x446b4a99,0x6bf65cff'
      },
      {
        input: ['13,6,224,159,177,59,65,120,26,168,41,235,185,144,147,38,128,57,178,156,27,167,111,203,8,221,47,247,140,41,78,154,47,46,57,225,105,122,89,132,35,130,111,220,19,3,2,147,60,180,47,88,92,158,35,100,123,82,91,7,124,169,161,171'],
        expectedOutput: '0x87804b49,0xb819c7c5,0x3b5669ed,0x5091e533'
      },
      {
        input: ['215,219,140,65,85,229,197,120,104,52,84,123,55,87,14,116,11,61,204,103,219,239,203,86,65,38,93,189,207,255,105,167,218,245,232,47,219,173,168,67,225,252,190,25,83,204,141,95,9,89,198,228,72,146,58,137,184,151,71,136,150,176,47,112'],
        expectedOutput: '0xe51ac111,0x572b6474,0xbd978b40,0x9d8f07a8'
      },
      {
        input: ['165,23,160,128,196,72,195,165,68,129,190,152,77,75,247,86,164,189,58,236,79,116,118,8,12,189,144,162,109,191,19,18,214,179,147,154,251,86,63,63,216,254,215,37,73,206,124,238,140,182,218,219,43,80,227,55,13,115,217,122,50,236,141,8'],
        expectedOutput: '0x3d8503ba,0xc9ade792,0xd89f731a,0x8d0b0a3a'
      },
      {
        input: ['159,32,162,154,118,226,218,78,224,177,116,41,128,240,23,12,166,242,231,209,66,203,8,80,62,226,202,113,206,87,121,110,119,28,8,238,254,226,60,222,148,176,7,20,160,31,32,71,17,7,24,83,210,33,163,17,3,110,130,209,197,251,63,61'],
        expectedOutput: '0xc941dea8,0x41efcb7a,0x7d0978a0,0xe685535a'
      },
      {
        input: ['23,72,43,21,42,103,243,190,24,251,210,184,26,242,255,43,250,24,126,204,57,34,221,60,144,95,13,85,91,77,146,114,149,189,136,191,37,123,126,61,118,80,245,144,67,245,187,61,13,58,9,70,92,231,130,236,70,143,65,161,220,212,20,113'],
        expectedOutput: '0xee7a1be0,0xb22a9f21,0xae65b7e5,0xa9ac0d17'
      },
      {
        input: ['145,156,49,182,23,175,243,142,255,233,30,66,222,218,127,235,20,137,49,112,112,179,92,182,66,157,88,31,113,108,144,3,8,193,185,31,112,173,173,112,150,204,178,116,166,50,95,186,187,144,42,43,67,134,225,133,35,57,164,149,165,53,152,173'],
        expectedOutput: '0x27706e9b,0x0516b472,0x79b9c636,0x1d47eaaa'
      },
      {
        input: ['246,81,205,103,254,122,215,148,70,137,8,236,187,103,166,118,247,208,161,58,86,131,192,122,188,100,15,98,153,167,15,144,248,220,247,247,87,206,139,157,87,148,138,19,251,48,137,243,1,43,45,87,174,237,209,106,82,224,204,235,135,220,123,128'],
        expectedOutput: '0x001e7d5a,0x95bb8959,0x44bc5011,0xa4187759'
      },
      {
        input: ['184,114,119,15,64,2,173,152,150,55,171,146,103,52,133,104,95,178,192,13,160,145,120,242,114,68,221,249,32,89,121,217,203,240,232,12,243,149,164,137,204,79,27,52,131,160,156,227,83,92,240,243,238,104,229,96,173,194,89,205,27,211,166,231'],
        expectedOutput: '0xee3a11dd,0x6360ece6,0x9ce40211,0x0ac7c4ca'
      },
      {
        input: ['195,143,243,182,36,151,64,241,230,91,37,105,252,193,76,79,30,61,66,12,165,39,108,82,233,197,32,5,152,198,236,92,85,223,18,122,118,82,107,92,174,144,197,170,81,18,249,111,79,59,123,244,98,231,71,75,173,103,80,69,45,60,161,131'],
        expectedOutput: '0x06443510,0xbf65b4b3,0xe7297cda,0xd3018bee'
      },
      {
        input: ['27,180,253,145,6,104,237,180,248,179,94,73,197,87,185,20,146,52,8,244,28,79,64,201,182,144,14,228,205,176,103,232,100,100,122,106,204,103,31,196,26,125,13,223,213,198,243,103,251,252,92,23,75,156,224,2,44,238,230,249,158,77,226,2'],
        expectedOutput: '0x49831e59,0xb3a083e5,0x13c74885,0x8f0f9715'
      },
      {
        input: ['177,92,109,125,195,140,65,222,9,78,189,222,21,177,70,16,173,162,39,248,62,7,250,106,245,224,100,148,45,70,150,222,162,3,91,101,143,156,67,153,235,1,119,0,178,189,16,95,95,55,87,157,62,82,8,51,50,108,199,96,178,94,62,84'],
        expectedOutput: '0x01170485,0xd4c323ec,0xf1eab3e1,0xf2b9119f'
      },
      {
        input: ['97,154,185,241,54,253,138,33,254,1,33,176,191,49,15,30,104,102,188,166,184,196,218,235,48,161,75,226,255,137,54,97,35,239,82,90,236,220,123,234,221,157,154,156,206,169,187,55,16,119,221,200,59,183,179,107,89,254,77,88,136,131,185,171'],
        expectedOutput: '0xd159931d,0x06e2af52,0x1d71d637,0x90ab12d1'
      },
      {
        input: ['114,11,5,95,231,129,73,197,30,228,97,236,141,28,35,157,147,1,102,206,184,25,57,17,24,134,106,160,9,35,75,124,47,81,219,22,210,36,219,240,8,61,220,150,89,0,51,237,1,153,187,185,179,245,203,203,123,53,107,133,88,182,1,135'],
        expectedOutput: '0x2891e568,0x9d3e9687,0x0264c9a3,0x8c4c543c'
      },
      {
        input: ['7,220,158,217,0,121,201,9,182,166,159,16,166,210,253,167,108,184,96,31,173,43,234,41,96,85,174,185,11,175,64,19,139,222,236,139,88,182,148,14,92,51,30,2,6,27,169,114,212,9,145,129,53,123,170,149,208,88,78,219,7,143,238,146'],
        expectedOutput: '0xfb25d68c,0xdd42509e,0xa1fe191b,0xe8a64bb4'
      },
      {
        input: ['109,219,30,197,145,178,212,237,230,242,239,236,14,152,94,226,161,239,99,214,106,14,108,58,102,186,21,110,73,4,0,183,223,30,124,112,209,80,93,183,67,76,163,81,228,1,51,133,240,150,92,90,164,200,148,11,130,169,121,204,173,121,131,140'],
        expectedOutput: '0x8240aef9,0x718db4bb,0xaaa16c01,0xb35cdd7d'
      },
      {
        input: ['152,255,252,105,80,89,32,147,165,195,228,137,196,23,15,180,173,107,14,82,51,162,93,181,75,214,129,249,79,4,133,231,4,130,80,84,219,112,231,129,51,203,10,247,226,25,171,143,132,185,225,183,91,62,109,167,20,238,160,100,243,37,75,247'],
        expectedOutput: '0x44f8e2c4,0x2cdf16e8,0xe7e1490e,0x2af8ed69'
      },
      {
        input: ['167,156,75,131,12,50,4,64,253,14,55,223,40,227,110,172,156,80,100,248,142,209,159,163,191,63,7,178,100,82,169,12,238,244,143,251,38,147,59,35,161,114,2,201,85,113,118,242,193,218,234,79,171,137,242,106,200,249,29,44,76,198,56,58'],
        expectedOutput: '0x8ac6457e,0xdb9ab1b2,0xe496630f,0xcad5a05c'
      },
      {
        input: ['187,199,53,225,90,112,5,252,227,7,197,56,120,59,42,57,21,20,137,192,157,123,43,101,117,72,146,193,14,202,251,201,146,49,171,236,161,176,232,132,183,174,189,48,233,231,105,255,252,242,191,153,110,234,255,227,50,145,164,65,91,159,10,237'],
        expectedOutput: '0xef4f7b5f,0xf279019a,0x9f0de9af,0xeb0a8533'
      },
      {
        input: ['208,181,218,114,101,194,246,29,112,179,77,90,155,182,89,151,169,24,48,23,3,47,250,53,192,158,118,28,61,129,9,14,54,227,128,156,166,118,185,22,42,6,112,197,188,201,92,101,226,140,124,229,188,118,26,124,20,145,152,82,18,162,96,72'],
        expectedOutput: '0x5018937a,0x717266b2,0x7e63ee7b,0x29231136'
      },
      {
        input: ['133,224,228,43,86,157,66,128,163,178,69,96,124,161,197,94,46,66,67,234,184,93,102,205,238,255,31,0,161,127,73,38,95,45,82,181,203,148,54,110,70,123,206,194,29,148,32,75,214,99,53,142,193,155,91,175,154,122,176,59,249,249,98,88'],
        expectedOutput: '0xf5e7f679,0x7ef4ae0b,0x1a05bc44,0x830dc316'
      },
      {
        input: ['38,180,14,241,72,68,96,142,191,46,81,220,194,113,39,152,213,92,39,150,248,130,69,146,253,245,206,246,238,48,79,21,228,93,6,44,161,102,186,96,149,11,61,87,125,100,240,82,193,23,232,185,153,45,75,150,35,25,141,17,73,220,38,45'],
        expectedOutput: '0x72ac70da,0xbec4f260,0x1c6c626f,0xe1c0ff02'
      },
      {
        input: ['57,45,89,218,147,20,58,40,31,119,128,156,220,112,238,157,135,214,86,32,4,161,183,39,187,68,56,4,32,95,50,89,140,139,51,31,159,109,72,191,229,200,91,193,56,74,94,191,32,180,223,36,85,150,75,16,218,132,21,250,227,71,83,111'],
        expectedOutput: '0x5975d677,0x45d49503,0xcce5a6fb,0xbaada6d5'
      },
      {
        input: ['210,134,142,114,244,214,49,217,158,140,154,214,214,248,149,247,172,117,27,1,11,103,18,230,235,39,224,206,110,52,61,64,186,203,178,174,162,227,135,64,112,33,23,70,25,172,61,197,33,89,199,45,192,217,19,171,0,243,121,110,39,182,174,226'],
        expectedOutput: '0xd6f23082,0xa6f96725,0x609327c6,0x9f338510'
      },
      {
        input: ['129,97,144,35,68,24,100,180,57,123,251,83,39,56,24,73,145,223,118,81,184,137,252,184,124,117,38,164,43,213,134,173,54,22,208,122,46,52,47,104,175,42,187,215,98,211,32,244,179,150,69,107,31,66,36,155,183,74,63,227,31,197,144,85'],
        expectedOutput: '0xbc5e82dc,0x58d080a0,0x3697a005,0x80a07d31'
      },
      {
        input: ['220,96,208,10,149,255,114,68,41,45,27,139,1,59,127,180,209,197,31,240,7,67,140,190,142,203,161,173,145,49,3,109,146,211,119,39,210,234,107,251,23,135,134,24,194,6,204,148,203,236,132,210,47,16,144,189,220,50,107,109,99,110,218,245'],
        expectedOutput: '0x804c66af,0xe88b1676,0xd69181f7,0x3d06275d'
      },
      {
        input: ['65,81,28,19,59,136,14,83,15,148,107,209,154,56,101,101,36,234,55,83,250,200,17,214,250,124,67,93,234,29,83,43,111,111,62,170,247,76,253,6,224,105,216,123,161,61,224,197,39,24,24,34,224,41,248,218,165,60,55,143,89,138,186,200'],
        expectedOutput: '0x64ad49d1,0x957a8f35,0x692deb8f,0x5f335822'
      },
      {
        input: ['250,248,115,241,68,112,248,37,217,208,160,122,13,128,63,53,152,88,87,120,129,79,82,39,139,138,182,229,20,113,173,14,105,32,0,174,145,248,211,106,200,115,229,213,243,36,10,140,124,97,4,254,177,87,37,60,225,219,33,245,76,207,4,182'],
        expectedOutput: '0x97893c37,0x442643c8,0xc1fde83b,0x3dbc535b'
      },
      {
        input: ['239,4,100,128,252,55,235,196,170,208,153,157,244,164,41,113,5,46,111,182,133,148,243,102,111,20,91,188,227,95,114,211,99,214,83,95,13,62,35,183,14,189,84,3,97,126,116,102,172,227,29,49,119,16,151,230,36,242,162,8,82,20,219,181'],
        expectedOutput: '0xab12a3fb,0xfc5a2e39,0x80388163,0x72b9adc2'
      },
      {
        input: ['234,46,21,247,109,56,174,123,245,3,126,86,129,242,189,45,213,218,94,76,234,245,51,14,231,213,22,57,234,241,239,212,32,4,204,141,60,122,8,50,125,135,136,254,121,69,43,79,31,137,155,9,126,206,24,102,164,46,159,142,32,142,98,64'],
        expectedOutput: '0x7cc17131,0x3d461281,0x207f78a3,0x707405d6'
      },
      {
        input: ['146,46,205,207,169,213,1,38,92,137,37,214,207,80,37,238,218,192,248,88,143,16,190,51,62,94,193,94,236,35,158,127,82,107,78,251,65,79,33,157,216,70,115,167,151,152,150,113,89,142,201,232,158,136,27,220,230,220,59,210,255,217,81,81'],
        expectedOutput: '0x4f2da4af,0xe50dbd62,0xf0e14810,0xd2860ac7'
      },
      {
        input: ['69,159,76,134,238,110,35,199,180,151,110,75,47,4,188,136,146,134,112,48,14,139,13,244,103,72,198,103,33,24,184,102,183,5,236,166,115,16,109,39,167,219,115,214,224,47,95,114,181,207,163,195,91,176,183,194,248,126,41,25,150,226,128,77'],
        expectedOutput: '0x470b4ea8,0x26e5cf42,0xabb13088,0xa4a619db'
      },
      {
        input: ['231,108,243,90,124,96,129,35,60,244,250,28,36,89,142,217,40,49,157,131,225,84,70,217,210,111,243,104,81,115,182,56,223,169,146,92,10,20,127,70,8,121,98,44,210,240,6,251,34,163,126,3,247,196,221,202,52,208,50,133,67,232,190,34'],
        expectedOutput: '0x61b68047,0x7abe5bc5,0x0ec1d33e,0x02c83b87'
      },
      {
        input: ['146,80,126,156,100,254,226,109,119,68,153,74,52,159,69,86,66,195,90,58,136,55,4,188,7,54,65,74,31,255,108,177,80,235,77,180,233,47,33,96,115,187,170,167,90,239,254,157,179,88,215,59,143,219,247,150,17,56,224,48,56,76,225,136'],
        expectedOutput: '0xb03492e4,0xd0c48cbb,0x9bef8416,0xcec5ff4b'
      },
      {
        input: ['55,46,60,32,93,94,129,208,25,43,120,115,27,118,16,206,206,231,9,93,194,0,243,212,56,211,4,112,31,230,248,87,20,53,119,114,147,248,66,172,36,186,31,63,48,48,13,254,23,22,91,218,22,78,174,78,33,178,191,65,152,183,152,173'],
        expectedOutput: '0x8e96f745,0x71b5fc87,0xfdbff3da,0x3ceee9ae'
      },
      {
        input: ['236,15,31,127,8,97,43,44,28,75,107,76,123,120,75,146,142,166,108,164,245,26,242,22,205,177,87,101,105,239,18,85,255,49,213,7,147,0,51,175,75,158,251,198,22,70,89,164,237,197,72,226,224,58,248,173,236,80,18,85,63,37,170,62'],
        expectedOutput: '0xad1cb47c,0x03bf322c,0x86a74bdc,0x83849d79'
      },
      {
        input: ['86,127,69,233,128,120,152,203,22,148,146,44,218,235,208,199,176,24,169,144,83,162,61,63,242,80,148,49,117,62,112,203,190,181,181,62,46,77,9,68,225,155,113,188,134,65,131,55,90,45,199,173,207,5,236,193,85,128,242,202,190,98,149,124'],
        expectedOutput: '0x463a4660,0xef2d63ba,0x8db7fbd7,0x2fbead71'
      },
      {
        input: ['24,74,186,70,152,196,138,121,95,251,53,230,61,185,29,151,230,228,68,181,233,48,118,62,176,104,8,110,203,158,235,227,232,165,41,128,105,179,250,201,175,47,175,236,232,204,131,206,176,199,131,154,247,249,216,167,98,225,21,45,127,0,16,103'],
        expectedOutput: '0x5f2d82d3,0x67f10bb5,0xd665172a,0xfa376e41'
      },
      {
        input: ['166,57,232,15,236,226,216,155,17,135,135,250,83,10,200,4,209,76,158,200,69,118,111,167,87,133,212,214,133,228,62,43,29,38,59,10,8,19,165,25,155,45,19,238,55,220,242,9,40,144,209,109,7,65,21,94,198,233,53,75,206,115,119,235'],
        expectedOutput: '0x14c507ea,0xf6760f79,0x419c1b87,0x48d671ec'
      },
      {
        input: ['153,178,245,161,197,155,186,96,200,206,79,255,170,65,8,210,210,218,63,217,27,84,55,225,62,108,44,12,223,163,247,120,85,237,25,27,136,212,123,80,162,202,79,76,12,88,30,222,50,93,183,77,178,238,46,240,91,90,252,58,254,243,179,83'],
        expectedOutput: '0xd8db4e7d,0xba6101ff,0xaceda3c3,0xc8bc8df7'
      },
      {
        input: ['224,204,110,104,160,234,184,66,180,8,142,192,96,172,158,146,10,85,223,188,68,13,172,159,103,168,217,101,155,140,185,124,89,39,228,249,17,157,60,198,165,202,134,5,119,37,151,129,122,118,61,190,131,233,93,234,145,55,80,44,195,9,168,28'],
        expectedOutput: '0xce52e1e1,0xa05c5a28,0x21fba2f1,0xff908950'
      },
      {
        input: ['48,141,22,66,42,82,8,207,28,142,212,147,179,107,20,46,225,81,236,100,58,74,78,203,129,158,248,68,167,160,97,216,45,119,26,87,201,34,38,229,176,250,121,100,101,141,146,70,223,126,170,25,200,249,229,73,151,221,142,63,125,239,23,171'],
        expectedOutput: '0x076d562d,0x71dd5734,0x344003ba,0xfb87e39f'
      },
      {
        input: ['102,49,2,47,83,41,20,3,35,141,103,137,27,249,207,250,120,122,19,64,115,248,138,10,213,24,73,83,7,96,254,109,145,0,156,228,41,176,232,77,62,79,214,89,73,165,83,193,31,102,1,146,95,139,157,52,163,230,135,170,71,133,23,216'],
        expectedOutput: '0x334867b3,0x9412ae95,0x7f1bcfcb,0x59f326d1'
      },
      {
        input: ['134,179,189,175,100,165,252,162,244,210,251,61,120,78,254,151,180,0,42,19,139,199,72,47,173,207,217,244,85,241,205,219,164,138,138,8,47,135,170,35,89,165,97,209,243,95,105,168,95,147,187,235,90,3,26,7,211,243,252,40,228,201,3,137'],
        expectedOutput: '0x8f619783,0x39505995,0x7275e9a7,0x1ac5da9d'
      },
      {
        input: ['83,141,145,130,20,60,165,110,225,6,63,213,102,168,125,197,59,56,176,149,60,202,157,15,190,153,55,162,98,58,43,181,199,189,55,220,249,220,74,218,227,137,175,73,50,44,14,109,101,191,3,161,137,160,176,71,57,231,234,155,33,21,80,232'],
        expectedOutput: '0x81bf3b8b,0xaca0eb44,0xaa7fd66d,0xfb09778e'
      },
      {
        input: ['210,135,196,203,99,14,166,70,152,85,143,202,130,158,55,231,93,58,136,230,218,56,46,19,31,24,174,64,45,254,40,0,133,237,203,233,251,113,47,147,199,191,93,73,93,149,48,186,207,184,160,170,240,206,189,15,230,108,79,20,106,119,20,240'],
        expectedOutput: '0x10f4803e,0xc2a43d37,0xf412bc82,0xa4bb1623'
      },
      {
        input: ['100,223,217,96,81,8,243,24,199,81,97,36,230,145,222,181,73,127,95,57,77,29,72,52,137,151,72,243,14,92,227,115,59,188,211,140,197,198,164,140,23,5,177,253,150,143,179,223,14,18,24,92,47,96,144,184,247,216,172,6,52,143,121,111'],
        expectedOutput: '0x8b003436,0x96e20517,0x903dc4ac,0xe5280740'
      },
      {
        input: ['76,76,252,17,18,160,157,42,166,78,39,60,222,218,28,236,237,52,72,28,149,216,213,140,176,129,146,228,16,11,84,92,87,80,109,106,240,11,148,150,89,187,211,55,150,239,36,131,35,108,159,184,69,116,69,245,245,215,218,6,227,46,98,58'],
        expectedOutput: '0x011db385,0xd3e91a3c,0xc5e23884,0x637cee7f'
      },
      {
        input: ['126,208,164,110,219,56,5,52,244,216,108,138,199,144,13,234,252,172,163,65,33,232,55,22,191,17,28,162,63,127,221,189,79,129,43,42,186,48,94,174,8,202,56,207,90,69,186,87,241,93,152,18,69,207,41,4,224,69,167,31,196,132,220,19'],
        expectedOutput: '0xe32ce4b9,0xc34a960c,0x7364416d,0xb5ea6b52'
      },
      {
        input: ['5,8,61,191,56,156,109,65,102,165,16,193,234,202,24,220,39,176,238,108,128,23,113,96,93,24,128,33,156,92,53,161,100,114,97,157,14,206,222,117,116,238,54,94,185,78,58,224,254,41,77,126,64,190,223,157,214,95,191,114,187,244,19,32'],
        expectedOutput: '0x89b094cb,0x47f159a4,0xa9339348,0x34a4a0a5'
      },
      {
        input: ['102,116,189,117,67,155,234,183,137,32,21,66,110,80,35,108,121,112,235,185,46,202,87,4,41,22,118,228,10,137,4,112,254,193,229,65,92,207,248,230,239,13,40,93,93,75,202,214,187,181,144,233,127,231,237,168,253,99,140,7,237,145,119,235'],
        expectedOutput: '0xf3b48ff8,0x19734c03,0x3732e41e,0xe2f37753'
      },
      {
        input: ['82,93,44,175,44,36,149,28,49,189,121,143,9,67,101,196,248,245,174,119,220,155,31,217,255,172,224,236,61,88,215,143,181,3,62,225,39,211,253,88,145,119,231,154,186,77,94,179,66,12,42,31,168,74,248,167,246,217,147,51,49,106,194,230'],
        expectedOutput: '0x89d382f2,0xa464cbb3,0x9468b808,0x078d0f9c'
      },
      {
        input: ['109,1,199,148,212,197,236,101,60,212,255,246,33,94,169,99,106,212,130,18,30,123,185,20,84,76,71,133,182,9,107,35,10,50,183,223,247,164,68,51,120,68,42,153,162,211,252,12,167,127,31,197,250,216,217,78,37,32,211,219,42,62,255,52'],
        expectedOutput: '0xc336934c,0x54fdae22,0xd0dafebd,0x1d354dca'
      },
      {
        input: ['112,182,19,104,90,88,155,210,156,197,107,62,153,104,74,64,231,105,6,225,66,223,47,103,0,2,66,42,64,65,94,176,248,114,24,82,202,180,37,102,121,144,164,18,248,238,83,223,88,89,192,154,56,239,1,56,241,67,98,49,133,193,226,125'],
        expectedOutput: '0xba80a9ff,0x731f6b10,0x175048d3,0x9748799c'
      },
      {
        input: ['51,250,207,253,174,244,99,40,133,7,58,125,245,141,93,77,230,29,231,31,13,232,87,254,44,186,48,177,123,18,46,174,12,253,171,187,242,14,227,119,21,29,244,10,171,81,88,145,111,63,176,124,40,8,122,84,194,170,5,61,188,51,235,201'],
        expectedOutput: '0xfdb2ffca,0x9e55ddc4,0x39f95859,0x2fb051f3'
      },
      {
        input: ['48,150,132,34,164,103,153,185,132,142,195,47,223,27,193,78,91,113,202,131,121,69,215,59,239,220,120,172,15,99,117,63,249,249,98,157,96,251,86,228,137,26,20,105,53,213,183,144,70,130,19,192,199,234,251,182,198,116,98,213,215,215,21,209'],
        expectedOutput: '0x30c5de68,0x2d9c9388,0xa451753c,0x6e8b578d'
      },
      {
        input: ['208,119,110,48,114,197,21,252,223,41,101,20,254,28,165,68,158,184,4,101,163,0,28,105,116,126,63,75,86,84,28,38,203,139,87,61,80,108,57,47,149,158,67,147,187,232,215,89,161,220,191,68,220,219,173,80,89,236,155,175,64,184,214,11'],
        expectedOutput: '0x4205e21e,0x3851bffe,0x90466cbf,0xc1b6c8aa'
      },
      {
        input: ['67,45,73,147,153,130,194,46,33,5,193,220,238,152,53,143,116,244,211,80,207,128,160,41,109,60,216,173,244,174,185,55,219,2,202,116,132,140,162,165,145,99,129,127,252,183,14,112,171,225,193,123,98,97,164,207,157,124,124,145,43,53,200,6'],
        expectedOutput: '0x5790e840,0x89cad3d9,0xeeba3405,0x833fe66b'
      },
      {
        input: ['55,146,123,188,30,29,97,176,129,227,47,125,154,62,237,69,31,174,192,129,16,100,80,173,225,205,63,12,2,7,18,58,154,141,246,184,171,87,104,44,58,152,169,212,214,150,26,245,69,218,119,85,63,199,2,32,148,65,44,151,73,62,209,227'],
        expectedOutput: '0x5dee14e8,0x3d963bfe,0x861a3e7a,0xdaeaf3f7'
      },
      {
        input: ['204,199,155,119,30,4,163,89,156,76,45,114,226,71,103,39,34,222,124,97,166,127,129,58,192,173,209,9,235,162,236,183,105,136,46,136,140,209,225,40,29,14,154,0,86,1,39,120,224,164,217,134,35,90,192,227,7,146,237,242,52,217,170,158'],
        expectedOutput: '0x1950b14d,0x8ad8df85,0x55d66e2b,0x40ec3f6c'
      },
      {
        input: ['97,216,38,237,170,7,21,199,21,175,199,107,177,239,227,145,147,188,23,182,22,215,153,29,105,134,16,158,96,186,60,193,146,98,175,60,105,196,4,126,116,203,234,37,186,205,182,77,138,205,3,160,164,157,190,14,35,206,172,131,136,232,69,26'],
        expectedOutput: '0xac1b146d,0x68c8ba23,0x9d788915,0xf479fc7d'
      },
      {
        input: ['74,244,87,179,184,91,49,44,38,27,81,225,233,7,46,115,212,50,19,121,207,209,135,242,159,51,118,39,27,187,66,101,175,153,24,103,244,73,148,26,101,229,251,78,237,42,193,193,92,212,58,43,166,193,29,69,244,147,109,15,78,175,116,253'],
        expectedOutput: '0xc9a7a6c1,0x8bcdd8ef,0x6c2c02f8,0xfe08ef03'
      },
      {
        input: ['72,140,101,60,214,249,86,59,222,82,137,203,124,74,141,216,30,199,3,196,137,32,10,125,180,119,141,2,38,1,0,110,142,101,170,100,94,0,159,60,82,40,8,206,114,149,166,144,92,169,85,229,202,95,99,126,214,240,128,252,241,128,106,127'],
        expectedOutput: '0x84453396,0xd578cf3c,0x9af0e1d4,0xb3a4cdf1'
      },
      {
        input: ['229,20,227,67,20,130,128,103,170,136,53,28,29,220,173,121,133,2,95,79,97,194,205,55,178,78,51,163,206,157,35,180,177,6,247,197,137,119,44,51,255,98,80,28,62,253,150,195,255,245,19,96,183,224,151,105,46,202,12,253,103,47,177,24'],
        expectedOutput: '0x18d0be7d,0xb2200ba4,0x62ca5791,0xcf37cd9a'
      },
      {
        input: ['54,168,221,191,32,10,242,31,108,66,60,170,63,210,109,62,199,128,158,126,97,53,231,143,255,243,140,102,35,61,126,89,230,92,24,6,102,10,37,210,77,97,124,140,51,233,203,250,106,105,120,203,159,95,90,158,83,231,5,118,36,131,207,10'],
        expectedOutput: '0xc62a9c79,0x650d6a9f,0xab8ede42,0x65c83bed'
      },
      {
        input: ['223,231,16,69,241,54,23,62,151,147,203,203,125,150,197,231,255,62,178,158,157,12,61,240,243,66,102,24,197,53,34,165,28,51,234,14,105,2,76,0,149,23,203,18,173,145,249,173,207,171,75,108,184,136,93,171,202,195,195,144,249,230,53,21'],
        expectedOutput: '0x4ebcf79d,0x9ed83374,0x5ec9a502,0xf9ad60b7'
      },
      {
        input: ['25,31,35,130,33,112,130,183,135,78,201,53,223,195,226,174,110,45,26,38,182,119,210,128,59,149,16,52,123,69,73,148,101,109,22,134,221,153,61,100,231,7,153,198,202,123,116,56,169,142,95,95,6,49,223,65,198,240,117,66,53,190,214,154'],
        expectedOutput: '0x7a90d3ef,0xf5a30221,0x3515ffcf,0x6cb47125'
      },
      {
        input: ['43,237,33,8,134,94,109,109,101,6,51,47,130,167,104,43,53,199,138,59,248,105,124,190,89,241,0,143,176,215,41,219,196,74,228,74,169,81,183,14,87,234,62,217,145,166,4,198,109,142,2,101,248,126,35,81,112,36,224,32,251,10,251,191'],
        expectedOutput: '0x0512e240,0x6dcd56fd,0x30c33e12,0x3b7478a7'
      },
      {
        input: ['84,223,9,253,48,192,12,136,170,74,97,59,240,102,1,93,244,3,194,236,130,229,62,242,9,30,18,4,40,13,195,125,237,204,122,29,140,134,165,54,208,7,113,192,109,115,29,97,118,223,78,248,197,140,234,206,170,252,211,211,10,150,80,247'],
        expectedOutput: '0x691b4ad1,0x99edc287,0xcb2db4db,0x2940d8ec'
      },
      {
        input: ['99,202,20,239,81,186,38,33,193,151,226,46,10,255,143,129,223,221,121,164,105,100,114,20,96,69,231,106,220,55,97,63,1,118,46,82,48,84,116,241,236,86,31,246,85,174,119,52,140,241,216,245,85,75,9,181,144,240,32,108,39,129,171,41'],
        expectedOutput: '0x65cff251,0x1ce4a04b,0x58cf0929,0xa11560a7'
      },
      {
        input: ['247,218,123,39,46,239,24,26,69,55,17,155,230,136,207,114,121,168,103,206,243,113,132,131,97,164,240,137,37,155,178,29,117,45,68,164,29,93,190,98,148,207,253,122,88,205,236,209,117,84,160,104,197,36,235,38,200,219,175,237,119,97,10,236'],
        expectedOutput: '0x0e353d44,0x4e7e6595,0xac1c1a65,0x9ef85077'
      },
      {
        input: ['143,79,144,172,172,79,14,64,30,12,187,118,217,167,72,78,251,232,182,192,12,161,231,212,125,150,193,244,248,204,224,135,27,113,51,199,192,65,7,222,77,194,85,38,106,157,116,101,133,42,38,145,204,13,101,73,163,38,61,155,242,29,34,13'],
        expectedOutput: '0x7485f018,0x2be9be65,0x789b0f1a,0x81c1e419'
      },
      {
        input: ['142,85,212,78,151,220,45,228,158,130,11,8,31,127,110,164,170,148,53,118,161,154,191,68,192,252,224,179,25,2,192,168,88,149,246,239,113,35,211,15,165,222,24,196,94,134,104,8,26,157,126,187,55,61,255,248,57,223,171,82,226,107,250,58'],
        expectedOutput: '0xc7a8d673,0xa8681590,0x066e8dfc,0xb227ebdc'
      },
      {
        input: ['0,241,41,113,20,252,129,186,219,153,126,57,31,231,65,57,132,191,244,188,252,243,180,53,211,95,135,181,202,130,239,203,115,24,60,135,20,189,65,239,86,192,40,117,167,105,174,43,40,162,231,36,150,155,89,105,250,225,30,197,99,13,144,214'],
        expectedOutput: '0x50c105f2,0xb81bb338,0xfe46ee1d,0x83cdba70'
      },
      {
        input: ['37,204,93,57,138,159,41,224,95,81,86,6,187,4,49,227,167,25,8,61,180,97,166,175,66,196,116,165,209,4,123,246,208,217,47,90,120,88,59,215,170,145,221,101,149,14,72,60,39,80,121,220,178,31,139,244,227,255,154,180,3,21,170,211'],
        expectedOutput: '0x33f903a2,0x4508c0a9,0x8456c7b4,0x00c26932'
      },
      {
        input: ['238,218,46,102,50,105,61,220,250,26,65,143,41,138,204,80,218,69,44,140,101,183,129,72,182,27,253,185,48,167,141,31,129,187,133,180,36,195,144,30,221,210,173,6,92,121,87,54,191,131,195,36,59,68,108,241,95,105,171,143,17,56,174,146'],
        expectedOutput: '0x8c10cf18,0x9ca8a85c,0x31d3516a,0x1ea1837c'
      },
      {
        input: ['243,52,70,23,247,215,53,212,169,226,219,5,92,50,59,27,181,254,63,240,66,171,226,161,21,141,49,38,197,223,184,184,19,255,207,10,214,4,223,127,230,186,132,66,236,191,93,161,190,156,146,0,72,116,162,93,1,211,131,198,178,59,126,198'],
        expectedOutput: '0x07d56c12,0x9d0ac8f1,0x82915ac7,0xb52be169'
      },
      {
        input: ['58,77,208,16,81,175,143,55,105,19,122,85,211,215,247,145,116,137,145,188,253,51,25,254,6,156,196,185,215,66,127,18,143,79,34,224,255,178,23,104,197,145,190,152,105,181,41,221,62,187,153,59,238,178,57,245,78,253,174,37,63,45,55,206'],
        expectedOutput: '0x7fc7937f,0xdf6330d8,0x729d176f,0x0ae8ef5a'
      },
      {
        input: ['124,90,174,123,12,197,228,209,87,162,106,192,87,147,157,149,78,54,208,61,232,9,50,54,6,224,91,69,13,147,19,137,237,193,5,249,134,233,202,221,139,52,157,226,200,58,119,22,112,71,83,88,80,133,142,86,101,234,155,114,125,174,252,106'],
        expectedOutput: '0xe9df5c0f,0x9e1c2425,0x1d421d76,0xdd10b023'
      },
      {
        input: ['111,1,99,245,234,45,211,117,98,112,87,42,171,206,64,27,21,148,116,101,25,2,187,127,236,86,241,105,4,237,211,115,238,54,104,216,100,59,77,198,172,164,240,87,114,48,114,135,196,230,236,222,233,167,93,213,253,78,63,1,60,18,116,42'],
        expectedOutput: '0x55d9433e,0x09177a2a,0xfd8eada7,0xfc8c0ed4'
      },
      {
        input: ['73,221,3,173,24,80,115,196,245,99,27,103,147,142,239,88,116,219,54,93,131,147,51,128,225,114,130,29,132,246,72,205,211,75,122,236,155,237,176,144,80,204,248,228,90,231,60,206,194,114,44,69,5,95,198,230,209,72,4,85,62,76,35,18'],
        expectedOutput: '0x31fd027a,0xb158d170,0x1a6b5700,0x4f793c38'
      },
      {
        input: ['151,157,254,50,139,174,195,219,122,187,191,212,162,251,163,100,109,207,170,114,46,112,89,255,184,93,84,246,169,119,8,64,21,6,114,160,181,53,123,47,240,59,4,146,54,167,247,164,118,161,22,164,17,111,163,201,204,247,191,117,111,200,181,132'],
        expectedOutput: '0x0b7ce43b,0x3ae3ddd7,0x8c4a3156,0xaa949f21'
      },
      {
        input: ['206,40,36,131,93,159,179,78,218,183,224,17,94,215,181,212,120,203,120,137,59,27,82,7,18,18,125,129,218,50,5,168,90,41,44,184,201,223,6,163,150,230,180,244,190,105,200,54,53,64,192,112,91,18,119,109,36,244,239,254,39,244,167,129'],
        expectedOutput: '0xb315c24e,0x76bca65c,0xeabe11cc,0x40789017'
      },
      {
        input: ['30,211,57,231,178,63,138,72,38,63,60,228,168,4,26,221,68,218,77,159,237,197,12,17,185,251,16,224,240,183,98,14,138,155,245,60,219,127,132,1,190,192,229,103,196,255,68,8,218,146,167,199,87,179,216,16,175,232,241,159,159,83,173,41'],
        expectedOutput: '0x3ecb524e,0x2af59401,0xca00125a,0xb691288b'
      },
      {
        input: ['238,162,101,201,33,233,202,224,169,175,71,109,175,139,117,137,29,28,80,116,208,40,133,127,17,118,30,176,201,203,218,183,109,63,129,142,41,75,110,210,251,181,64,170,65,181,51,94,210,131,211,162,171,88,33,188,206,63,109,151,10,71,78,119'],
        expectedOutput: '0x03548c6f,0xad514b55,0xef70ed0e,0xc0468841'
      },
      {
        input: ['134,207,5,175,27,116,130,22,41,194,192,106,119,243,201,73,118,156,235,33,244,12,222,194,75,75,89,85,146,167,204,24,119,210,200,146,70,74,168,111,12,104,218,131,91,163,205,209,63,184,242,51,197,208,245,16,27,78,102,173,245,50,198,108'],
        expectedOutput: '0x8aff3ac1,0x685a88a3,0x1063084b,0xe5b6f8c5'
      },
      {
        input: ['4,142,254,74,216,166,186,228,14,148,103,105,55,52,58,118,237,45,169,178,253,158,194,25,236,40,198,225,91,140,78,95,26,76,170,242,243,100,214,1,248,62,107,47,114,165,165,95,210,78,17,208,236,212,233,216,252,175,185,87,60,7,183,86'],
        expectedOutput: '0x8267dae4,0x60e1b4d2,0x79fd96de,0x7d015065'
      },
      {
        input: ['84,97,73,71,197,31,72,189,93,179,236,208,89,145,47,43,223,65,251,203,21,228,163,17,148,92,105,208,100,32,38,184,129,111,255,70,143,71,3,236,251,239,188,84,128,236,127,95,45,123,42,66,95,205,83,243,41,188,195,141,220,234,69,93'],
        expectedOutput: '0x8a026ed7,0x7049553a,0xce8dd98f,0x575e636c'
      },
      {
        input: ['89,68,163,232,140,166,213,135,149,145,219,21,125,90,116,170,213,158,236,53,107,64,40,149,252,236,34,217,214,104,54,47,172,218,24,56,128,237,191,22,126,154,43,252,245,160,166,202,62,147,255,170,211,40,63,207,20,97,168,234,201,223,25,118'],
        expectedOutput: '0x46a7c2bd,0x48a3721a,0x5ee2cb6f,0xaf80d5e3'
      },
      {
        input: ['185,49,174,57,30,110,79,157,8,123,153,253,27,63,200,89,210,199,3,165,239,66,117,3,164,29,237,109,252,7,227,181,56,146,239,87,0,62,244,8,185,141,6,212,204,206,46,159,149,49,68,133,116,185,136,24,215,118,133,211,125,105,137,181'],
        expectedOutput: '0x2a465967,0x01211b4a,0x27d3cb5e,0xf580d317'
      },
      {
        input: ['251,120,12,251,182,0,3,112,141,9,68,90,215,114,249,109,164,61,242,24,247,122,48,206,240,181,161,109,30,42,35,25,162,47,20,89,48,24,201,189,33,13,23,249,128,16,102,36,78,88,60,69,210,108,19,195,33,180,48,64,223,83,89,129'],
        expectedOutput: '0x10c600d2,0xe7130e50,0x374b89e8,0x41a622b4'
      },
      {
        input: ['131,110,218,179,134,163,112,167,177,136,160,49,152,6,85,230,94,145,43,49,253,62,244,30,243,36,94,210,120,184,83,251,38,46,174,172,209,30,83,130,166,244,179,63,250,8,37,89,153,81,138,150,143,126,181,130,162,19,84,26,203,168,21,241'],
        expectedOutput: '0xb4c99e3a,0xf9a25afe,0xb6e1571b,0xdfc62e5a'
      },
      {
        input: ['214,195,157,167,226,241,42,136,229,221,199,223,230,237,56,127,62,194,22,205,64,203,80,227,222,164,253,170,76,19,155,34,214,57,202,184,42,244,65,15,209,8,238,183,245,39,55,51,233,77,1,42,24,81,13,246,245,10,160,66,29,60,100,244'],
        expectedOutput: '0xbf5211d6,0xdfcbcefb,0x85fd7dcb,0x776fcb4a'
      },
      {
        input: ['117,46,172,159,34,237,174,244,246,156,171,235,195,226,31,173,47,32,215,71,113,228,62,102,238,222,168,12,26,13,0,143,59,172,46,94,154,220,82,144,121,253,123,60,224,154,233,15,186,192,87,43,164,149,146,147,115,58,159,142,71,159,29,131'],
        expectedOutput: '0xe4aa5295,0xaf765170,0x1454ab97,0x6033fa1c'
      },
      {
        input: ['75,76,225,229,40,51,117,161,48,241,222,16,139,199,32,70,136,119,113,44,12,3,191,127,62,94,13,133,253,43,8,73,119,233,46,159,28,164,65,77,149,31,93,32,230,125,102,110,244,216,155,0,219,90,128,25,185,141,159,182,184,167,255,47'],
        expectedOutput: '0xa670fc02,0x4fc72901,0x255bd818,0x75a5f1fa'
      },
      {
        input: ['145,46,207,173,210,16,250,103,47,88,135,21,213,238,132,202,198,31,202,161,121,74,187,50,216,90,233,144,1,232,192,146,22,143,64,232,159,58,79,206,146,215,227,104,197,103,50,139,134,252,44,0,71,231,50,31,65,27,175,67,4,111,213,26'],
        expectedOutput: '0x90d460e0,0xd16c1467,0x57a8f2bb,0xc23e54f1'
      },
      {
        input: ['254,21,3,157,80,82,107,226,41,79,74,238,182,124,121,61,121,166,61,192,141,111,223,207,139,142,18,143,254,231,169,252,253,172,154,77,255,5,47,40,84,122,23,11,246,144,72,111,54,133,47,196,244,14,147,127,157,165,14,155,140,184,151,137'],
        expectedOutput: '0x787555f3,0xbea1c6f1,0x59650bb2,0x3d828bea'
      },
      {
        input: ['100,49,214,99,55,6,140,139,128,163,150,118,51,222,230,106,99,21,46,88,36,193,215,193,102,230,92,242,158,243,124,2,37,82,102,92,88,242,231,216,149,126,79,200,92,53,50,192,74,96,24,110,33,239,47,135,213,139,122,115,127,246,118,164'],
        expectedOutput: '0xba9a9982,0xd47b9327,0x11e53c51,0xec22851d'
      },
      {
        input: ['72,220,0,161,206,231,121,99,101,200,43,194,253,94,130,72,190,154,182,224,137,230,103,95,113,225,210,240,215,72,148,32,36,148,193,242,124,58,85,225,3,129,163,0,223,37,72,157,191,255,125,73,229,229,168,86,198,122,71,158,195,219,190,231'],
        expectedOutput: '0xddaf22af,0xfb13e9a6,0x1ad4078e,0x35a57680'
      },
      {
        input: ['112,127,218,236,185,47,205,188,176,113,189,143,150,5,45,86,4,170,159,233,143,71,64,86,193,135,244,132,98,178,108,210,49,70,190,234,117,140,167,38,253,100,181,147,105,226,233,110,141,136,87,28,207,151,114,145,30,102,21,129,24,129,83,73'],
        expectedOutput: '0xecabafb1,0x43169fb4,0xba86f0af,0xc8d4ca1c'
      },
      {
        input: ['199,18,52,61,158,219,99,155,63,24,46,168,251,24,22,136,160,110,164,112,5,23,1,36,125,22,165,150,152,248,223,95,10,19,156,168,238,255,67,45,24,114,214,19,138,236,155,42,90,63,154,96,86,155,132,212,178,41,106,74,33,73,169,44'],
        expectedOutput: '0x18765cc7,0xa9429c0d,0x7af82dbd,0x6e9d816b'
      },
      {
        input: ['93,70,212,75,69,24,121,93,138,79,112,20,59,11,62,150,75,217,246,161,116,122,117,38,163,223,112,196,41,26,240,134,96,197,209,165,221,74,3,103,153,115,123,213,127,185,107,202,146,97,107,7,219,225,45,126,192,158,66,233,184,51,111,24'],
        expectedOutput: '0x09dca9d5,0x5342b108,0x46da2ff9,0x5607fd26'
      },
      {
        input: ['248,65,189,213,139,192,60,37,52,183,250,179,112,101,125,3,198,232,10,161,201,55,31,138,213,97,115,141,148,227,165,140,36,99,97,175,35,157,212,87,84,206,10,197,51,135,200,249,112,210,154,57,9,185,195,223,27,55,108,175,26,18,60,62'],
        expectedOutput: '0xe7ba41ed,0x8fc50f21,0xa9ebbe46,0x698bdef7'
      },
      {
        input: ['117,157,237,152,59,194,240,143,144,250,84,196,130,28,189,242,238,88,43,248,17,239,215,44,38,67,220,64,85,24,126,202,181,107,99,240,45,83,128,190,77,212,130,207,241,63,193,223,151,237,215,169,220,174,213,2,242,177,66,71,201,192,18,127'],
        expectedOutput: '0xa3deb466,0x6a41770f,0xca85d4c8,0xb79c894a'
      },
      {
        input: ['43,117,111,89,200,239,23,21,196,153,229,181,216,166,148,112,147,108,25,111,26,238,113,12,160,179,84,105,115,102,232,159,219,88,248,163,71,15,184,11,168,157,192,128,68,85,240,215,193,9,71,219,248,184,232,152,108,60,1,223,162,234,126,125'],
        expectedOutput: '0x310edc7a,0xab6134f3,0x6fe5c132,0x7039420d'
      },
      {
        input: ['66,118,32,137,133,216,149,45,118,85,174,186,170,158,145,107,168,216,71,160,145,47,56,253,107,57,220,13,35,91,138,101,209,170,239,87,130,132,132,248,217,50,178,132,209,68,239,121,28,54,25,173,101,81,170,208,138,135,221,174,226,103,19,179'],
        expectedOutput: '0xec8688db,0x1c9715e8,0xca65fe76,0x198c379d'
      },
      {
        input: ['17,2,10,148,134,143,140,96,193,63,228,146,131,211,11,159,10,36,77,111,117,247,64,0,126,29,174,96,133,193,20,150,196,30,42,74,173,183,170,111,246,142,1,121,98,13,24,108,49,101,219,167,93,27,167,219,57,85,60,190,22,80,84,218'],
        expectedOutput: '0xf8303638,0x3fd1353e,0x263b25fe,0xc5d3a3d9'
      },
      {
        input: ['110,127,37,28,54,207,139,44,94,140,165,192,153,189,44,203,35,7,114,128,35,25,91,92,110,151,26,132,231,110,95,86,237,132,114,35,83,253,79,177,137,244,113,35,178,157,238,213,165,96,85,200,121,176,36,231,72,62,107,47,172,202,133,154'],
        expectedOutput: '0x618fce70,0x84e8ff25,0x59ccc0f6,0x24b05917'
      },
      {
        input: ['78,247,189,162,244,13,83,126,1,197,161,179,98,143,136,7,239,221,207,104,142,243,79,214,49,186,5,222,133,139,120,211,130,53,117,119,66,201,245,68,142,150,247,240,37,128,248,20,93,199,124,235,187,203,193,236,133,199,202,10,82,66,222,212'],
        expectedOutput: '0xf5c0f439,0x35431cb9,0xd3148905,0xd653386b'
      },
      {
        input: ['120,83,75,186,28,64,254,170,214,246,155,251,118,147,15,211,90,139,191,21,86,128,2,220,71,204,230,153,15,196,110,135,24,185,65,52,250,64,223,208,54,122,204,172,13,219,127,103,103,62,125,189,191,127,153,6,75,128,160,90,68,14,225,92'],
        expectedOutput: '0x8cb7026a,0xa79d0b11,0x4261a73b,0xdc9a8fe4'
      },
      {
        input: ['199,35,145,193,99,112,146,153,234,94,69,247,57,196,94,160,3,219,94,194,90,247,200,166,119,104,0,188,118,226,24,62,5,169,255,104,25,145,1,3,239,70,250,41,10,89,201,13,52,39,207,143,31,152,53,150,0,53,82,119,23,107,181,28'],
        expectedOutput: '0xa44f7664,0x6a97f78d,0x73d2e2c1,0xc9d5ef47'
      },
      {
        input: ['20,180,132,46,70,133,49,53,203,44,94,214,133,40,227,185,79,179,72,110,75,125,5,75,179,87,194,202,194,119,231,215,44,107,5,114,241,54,167,188,98,6,146,231,46,118,161,125,41,233,236,116,103,241,191,26,72,130,228,11,249,203,226,37'],
        expectedOutput: '0x2c64c30e,0x9eda5571,0x07a25418,0xf4661bff'
      },
      {
        input: ['55,231,151,40,29,63,228,128,69,119,103,115,237,8,240,22,242,220,138,89,205,73,115,22,203,87,33,197,35,3,234,90,234,130,130,7,193,102,135,6,221,239,121,202,247,105,224,233,70,106,66,19,180,181,41,127,13,74,68,48,77,47,138,55'],
        expectedOutput: '0xcc0c0065,0x3b394c96,0x29201a2c,0xf1dd1fd0'
      },
      {
        input: ['177,12,63,114,114,198,120,80,181,241,26,173,90,251,150,160,101,217,180,25,142,221,153,155,40,221,203,117,12,85,173,189,97,236,47,212,178,167,36,104,152,62,21,243,57,171,147,159,132,71,184,19,37,81,174,77,47,122,194,59,207,111,249,49'],
        expectedOutput: '0xc588949b,0x7316ab80,0x6db83633,0x65cc93eb'
      },
      {
        input: ['91,40,5,14,208,41,118,104,103,139,91,161,54,239,64,187,54,248,206,91,74,124,168,121,246,107,180,198,218,173,247,54,214,252,68,166,37,186,14,140,69,106,45,123,89,109,54,143,102,4,235,176,129,147,41,119,254,221,61,217,139,52,15,97'],
        expectedOutput: '0x12865956,0x1cb8be08,0xaf329270,0xb016f074'
      },
      {
        input: ['48,83,7,85,13,21,226,82,127,15,205,216,125,4,104,227,8,83,147,137,230,188,1,229,153,62,190,36,115,205,133,163,32,140,249,45,162,219,127,33,234,76,250,103,80,98,74,89,181,221,226,155,153,227,128,51,34,62,87,149,11,221,56,43'],
        expectedOutput: '0xebdd1b56,0x55dfbfb1,0xbbca87f4,0xdd53dcf0'
      },
      {
        input: ['105,49,88,11,12,215,45,247,36,39,94,116,137,169,205,62,134,176,217,32,147,90,83,181,152,170,74,164,135,131,207,241,180,40,252,193,255,41,184,35,80,22,152,217,191,101,23,70,21,241,102,169,75,185,94,227,99,169,135,235,44,87,220,224'],
        expectedOutput: '0x32793a2d,0x9f22ed89,0xcd741e4d,0x035243f1'
      },
      {
        input: ['127,216,161,126,2,89,162,82,112,58,44,47,159,67,117,181,52,219,94,127,148,188,99,248,101,234,227,145,65,191,114,192,151,19,63,153,109,225,236,221,27,24,12,186,91,130,111,144,93,205,15,242,138,114,234,239,93,205,129,158,140,243,95,35'],
        expectedOutput: '0x0fc91b58,0x45c1114a,0x054bd9e7,0xcdf3f796'
      },
      {
        input: ['6,158,189,115,127,169,80,154,193,93,84,28,223,196,172,60,145,188,46,27,46,24,11,139,229,140,42,113,127,137,149,133,39,82,249,166,251,73,64,188,166,148,216,133,88,133,194,234,65,240,5,111,9,16,251,238,156,37,96,27,174,245,161,213'],
        expectedOutput: '0xb3e761e8,0xcc720f8e,0xd5041bff,0x09b71dfb'
      },
      {
        input: ['71,154,123,66,227,187,254,138,79,214,15,168,91,209,146,156,194,151,12,203,168,7,185,68,44,25,96,218,14,1,175,85,155,42,151,126,229,149,8,52,108,24,220,199,233,110,100,171,6,112,118,174,119,48,242,163,73,82,125,88,83,44,173,238'],
        expectedOutput: '0x2cd089fc,0x51ab1967,0xd723757f,0x1134fce9'
      },
      {
        input: ['86,69,109,59,218,117,111,70,141,76,14,119,186,114,34,192,226,153,110,89,201,97,252,18,179,121,106,7,165,24,245,251,93,98,54,55,216,165,126,101,241,140,220,172,254,255,108,224,152,219,57,97,60,53,115,239,174,222,246,83,246,236,78,83'],
        expectedOutput: '0x0003cc63,0x852df1f8,0x075ad6f3,0x741c29fa'
      },
      {
        input: ['78,132,138,38,41,8,140,27,148,104,199,146,103,51,114,255,14,171,96,74,224,212,58,142,178,48,225,168,28,47,251,107,179,133,145,221,142,29,248,34,134,191,181,237,242,39,237,1,211,77,75,179,33,133,66,211,182,35,123,210,83,118,61,6'],
        expectedOutput: '0xbafff2e7,0xc9edd263,0xd95b1f00,0x9abec232'
      },
      {
        input: ['252,207,227,138,236,219,172,114,154,97,96,141,137,77,142,92,154,217,15,188,95,81,143,21,117,11,231,200,129,37,206,125,244,178,7,224,141,180,83,40,21,179,181,158,0,67,250,154,28,10,86,123,91,230,144,208,241,120,152,114,157,103,240,145'],
        expectedOutput: '0x266f5bd0,0x1f56fdb7,0x5e593405,0x166f56d5'
      },
      {
        input: ['25,247,113,166,171,196,206,193,119,131,95,119,198,90,18,227,100,104,94,191,78,239,144,63,103,40,178,4,143,162,149,168,153,6,79,69,203,29,6,66,161,101,186,103,191,204,74,35,52,169,227,131,152,115,194,255,155,116,3,43,22,152,211,176'],
        expectedOutput: '0xdc8c10a9,0x47d72517,0x9f461bcf,0x329e14e7'
      },
      {
        input: ['158,34,245,105,64,251,172,225,96,102,72,32,50,147,67,102,60,38,233,212,153,172,211,53,32,214,96,55,110,51,231,12,86,220,118,150,215,34,119,55,136,191,87,186,82,155,32,142,193,10,98,91,182,53,144,214,11,240,13,121,35,244,134,121'],
        expectedOutput: '0x9f40f105,0x09eb80ce,0xbd486ad2,0x5cd54324'
      },
      {
        input: ['208,252,15,167,30,134,223,166,70,54,96,152,209,128,39,147,138,137,238,64,191,126,23,202,110,36,68,145,25,202,11,233,198,26,145,228,161,112,138,231,166,234,127,120,106,166,11,245,48,249,53,239,119,76,185,229,113,253,118,138,199,129,115,141'],
        expectedOutput: '0x9bebdc10,0x9924657f,0x06d62279,0x9ea61733'
      },
      {
        input: ['156,4,113,61,116,251,36,27,229,163,147,80,74,158,69,122,151,122,105,14,199,34,243,56,32,105,194,231,235,53,117,135,58,230,196,174,226,232,201,199,139,92,23,213,250,92,79,145,215,184,159,158,219,146,214,251,252,152,226,231,205,87,110,7'],
        expectedOutput: '0xb831a095,0x1e88a313,0x9223e053,0xc1bfab44'
      },
      {
        input: ['62,50,182,32,26,127,231,165,220,255,123,214,91,202,104,50,131,7,208,94,154,166,89,150,62,59,125,12,147,235,19,209,29,201,241,55,73,216,220,37,215,87,251,51,34,99,101,165,107,54,3,5,220,92,155,27,151,24,39,42,3,58,251,32'],
        expectedOutput: '0x3d0cdbc2,0x92ebedee,0x18e8ea70,0x7997bc05'
      },
      {
        input: ['4,236,87,77,197,51,114,156,139,109,207,173,209,53,82,60,107,85,65,71,177,220,98,72,244,137,115,247,196,110,23,200,91,110,21,32,161,135,188,44,244,140,217,197,193,43,1,44,128,66,115,49,30,214,122,18,95,237,9,35,91,32,235,182'],
        expectedOutput: '0xe1327887,0x1b3297fa,0x6dfc4be8,0x66c53145'
      },
      {
        input: ['142,0,214,48,135,147,92,124,31,54,65,224,97,67,12,226,133,127,19,164,85,141,182,181,122,192,216,214,224,196,140,111,196,99,159,76,246,251,200,21,49,9,245,147,76,1,117,210,128,136,118,214,22,44,139,144,236,99,102,205,39,243,60,236'],
        expectedOutput: '0x5abdead0,0x5b3c5e99,0xff62ef7f,0x7774c50a'
      },
      {
        input: ['86,219,56,76,214,0,97,8,9,86,155,86,87,16,40,215,152,158,173,174,202,56,63,183,156,165,132,195,152,192,175,238,155,231,58,113,231,155,121,241,241,20,71,72,36,111,32,189,13,205,107,215,6,170,142,162,80,18,101,232,210,21,215,109'],
        expectedOutput: '0x083d23b2,0x9c345f24,0x28c98a7e,0xe2c1f608'
      },
      {
        input: ['252,17,223,228,173,88,213,158,109,28,231,145,139,7,78,152,212,186,111,218,100,254,124,180,16,226,157,227,247,116,80,243,133,47,215,50,136,172,209,245,200,184,134,83,191,213,235,147,143,91,110,243,89,234,168,105,204,69,76,195,185,157,183,62'],
        expectedOutput: '0x913f068c,0xff7e7603,0x16fd48f2,0x2a3afa36'
      },
      {
        input: ['204,142,113,84,59,66,73,3,250,208,87,185,165,66,76,52,157,186,39,246,165,207,96,113,20,172,53,205,73,236,12,22,122,125,106,181,191,180,185,185,132,16,114,41,82,190,93,240,121,132,230,30,84,70,143,104,243,196,54,60,176,66,82,43'],
        expectedOutput: '0xb786eadf,0x2965315e,0x6c7e9176,0xbcf4b309'
      },
      {
        input: ['191,189,224,126,113,153,55,245,169,169,30,252,103,123,236,224,255,210,254,83,25,142,188,12,82,242,72,3,52,155,46,243,88,14,113,201,168,168,190,81,81,220,77,184,87,57,153,86,12,151,170,37,37,102,49,120,88,121,123,140,20,169,127,108'],
        expectedOutput: '0xd495f8e2,0x3173d10d,0x5578f7cc,0xb483878b'
      },
      {
        input: ['183,240,53,95,152,243,177,233,207,254,161,38,56,58,125,68,210,39,105,247,141,154,111,229,19,234,113,40,147,240,148,75,224,202,170,120,189,91,97,141,90,2,179,146,61,48,214,15,87,63,6,228,217,118,201,236,96,58,20,244,42,169,63,10'],
        expectedOutput: '0xa11a5e9e,0x02b1e9dd,0x702b1bd5,0xcee3b67f'
      },
      {
        input: ['115,233,130,48,69,227,189,159,230,113,49,35,161,7,50,249,70,56,221,31,174,167,11,15,225,32,3,12,201,66,22,60,43,153,108,112,124,42,15,98,155,64,133,60,71,183,53,141,240,19,172,158,186,184,173,155,216,176,167,161,242,190,221,30'],
        expectedOutput: '0x59147d0f,0x52e799ee,0x1aef868d,0x255817f8'
      },
      {
        input: ['87,73,142,211,115,158,54,14,222,187,75,38,115,128,179,99,147,96,1,77,24,175,233,240,95,144,145,82,78,110,112,165,183,254,121,43,156,175,57,123,106,132,161,221,5,84,64,152,180,66,230,204,241,207,188,80,95,77,162,174,187,18,83,115'],
        expectedOutput: '0xe2afef1f,0xe29ead45,0x30bcb696,0xc3c2e856'
      },
      {
        input: ['17,204,158,173,123,215,40,230,92,201,195,97,30,4,249,210,70,223,159,55,174,91,135,14,169,42,188,100,60,15,215,77,220,117,251,87,77,35,61,169,237,1,10,11,5,3,221,75,227,124,130,145,216,9,159,129,51,91,229,112,107,189,189,71'],
        expectedOutput: '0xf061ebe0,0xb3385827,0xc3891e85,0x1242e83c'
      },
      {
        input: ['50,184,158,127,220,220,40,201,221,50,212,226,54,177,45,25,46,175,170,6,184,74,135,236,165,108,92,16,41,25,87,92,210,246,219,174,210,4,119,175,54,75,145,108,252,190,133,42,109,48,48,37,122,183,17,31,36,109,48,77,135,135,169,89'],
        expectedOutput: '0x170a4bf5,0xe8f57059,0xd5e2a302,0xc4715a38'
      },
      {
        input: ['125,133,7,79,137,126,254,191,201,143,44,197,77,177,240,186,225,32,224,91,216,241,123,252,95,171,73,230,50,243,63,176,120,70,255,1,196,254,192,141,141,236,82,219,158,66,149,127,99,117,219,59,103,86,55,198,1,128,172,51,115,235,227,235'],
        expectedOutput: '0x1967c10b,0x167d9205,0xa1fbc1ec,0xd0ef2985'
      },
      {
        input: ['49,227,236,245,225,173,130,110,153,212,73,55,23,223,183,122,84,146,181,187,232,236,129,233,108,45,28,224,24,0,203,73,227,184,62,196,101,192,50,254,149,124,54,172,91,237,38,175,127,219,107,103,199,236,80,51,26,108,19,50,108,223,124,79'],
        expectedOutput: '0x3499a727,0x4a9ac1e9,0x5b21c15a,0x0807cc54'
      },
      {
        input: ['151,186,19,252,123,70,250,16,194,48,188,29,29,226,204,156,189,55,3,132,36,83,183,62,192,203,112,44,170,236,124,65,167,143,61,34,213,55,50,151,104,238,180,133,208,129,34,141,184,37,17,220,121,200,26,57,147,139,101,61,119,225,126,30'],
        expectedOutput: '0xb301de8d,0x2541fed8,0x294c7c0e,0x15417952'
      },
      {
        input: ['113,187,64,70,243,114,222,91,96,146,224,48,19,2,189,204,40,206,168,161,151,195,218,42,78,63,104,197,33,230,228,146,162,36,216,149,151,182,240,247,73,208,40,92,211,229,40,251,180,209,156,75,148,118,117,226,181,221,167,214,196,139,104,102'],
        expectedOutput: '0xb11b7d2e,0x7e25b9e5,0x94a909d0,0x79cf1693'
      },
      {
        input: ['176,65,251,71,247,235,62,64,187,102,157,142,76,197,137,0,150,37,75,42,155,192,12,81,158,180,39,98,63,144,200,239,209,195,54,200,174,117,9,105,219,166,248,39,107,129,39,2,167,114,44,66,51,57,147,209,237,187,51,44,75,251,28,28'],
        expectedOutput: '0x0fcd7c50,0xf367fa46,0x05726f6f,0x1208ef7c'
      },
      {
        input: ['190,82,228,108,199,237,213,163,147,205,202,255,79,242,1,246,100,45,56,151,102,204,104,83,135,155,128,210,150,156,238,84,238,210,192,182,192,150,89,83,99,35,82,178,21,83,168,122,129,225,17,231,173,122,59,52,21,187,6,172,87,244,0,69'],
        expectedOutput: '0x8177492a,0x87b06e1f,0x5674b77e,0x554f9b75'
      },
      {
        input: ['198,193,251,134,87,84,218,186,120,44,109,141,128,21,7,1,246,25,232,163,147,35,215,168,222,221,84,53,209,85,123,152,22,118,30,109,203,248,39,67,37,148,208,165,170,216,166,160,241,142,68,132,178,27,44,144,249,129,198,202,214,65,98,236'],
        expectedOutput: '0xaed16494,0xdd13105a,0xafb4b036,0x758a0919'
      },
      {
        input: ['183,129,89,130,121,128,197,158,21,150,67,191,110,233,95,95,120,163,227,42,191,15,186,184,144,128,130,102,193,229,82,121,102,171,251,223,44,193,126,65,87,193,0,197,171,95,36,35,3,7,77,194,22,7,122,167,136,252,13,73,225,96,194,71'],
        expectedOutput: '0x3d5b0c14,0xd33fe7c1,0xdfaa0dd0,0x8303c52a'
      },
      {
        input: ['11,190,39,55,127,165,120,214,102,120,155,17,216,191,52,219,198,129,157,220,137,23,131,17,19,145,90,245,241,29,60,252,219,99,52,90,8,172,48,111,37,203,128,253,138,181,216,80,54,117,44,191,140,176,208,159,65,43,148,50,72,209,46,35'],
        expectedOutput: '0x8b7cd4fb,0xbd0829c5,0xac7412cd,0x82be101c'
      },
      {
        input: ['52,98,125,61,15,173,172,52,120,44,49,2,225,9,82,24,126,126,215,10,46,168,169,111,211,62,161,27,15,208,62,67,50,187,128,65,104,44,117,224,89,166,226,58,175,52,82,45,178,42,55,225,210,225,80,165,31,242,192,46,194,254,113,244'],
        expectedOutput: '0xa35df724,0x3cb073f4,0x36cee03f,0xab981f61'
      },
      {
        input: ['185,242,54,33,30,171,1,119,82,227,178,1,23,4,47,201,46,102,170,0,71,251,165,102,237,101,148,175,99,6,163,28,248,217,61,22,133,62,142,215,33,64,216,56,68,7,2,115,110,172,115,181,167,25,28,148,126,176,67,226,182,231,254,174'],
        expectedOutput: '0x60051601,0xa604e98d,0x09635d7b,0x99b2374b'
      },
      {
        input: ['192,60,197,69,122,83,28,156,147,245,212,215,252,214,74,106,131,190,32,42,215,60,191,85,236,2,55,163,233,54,81,170,114,22,239,236,105,12,136,252,1,93,212,253,51,30,104,182,220,136,225,179,196,160,9,176,162,64,83,140,118,165,54,232'],
        expectedOutput: '0x8f05ea68,0x4003a38b,0x8aa5418b,0x84eb39f5'
      },
      {
        input: ['187,37,213,37,49,93,33,50,186,245,48,238,20,152,164,240,32,133,164,228,37,173,148,200,237,232,84,100,141,138,76,72,175,33,109,225,127,143,19,57,132,67,39,152,219,204,137,251,81,45,223,119,218,116,63,199,92,147,43,233,29,120,49,204'],
        expectedOutput: '0xa68fe4ef,0xc8292ef9,0x03dffd4e,0xe19cc18a'
      },
      {
        input: ['153,159,173,24,46,193,82,178,4,121,75,224,69,212,219,151,1,187,14,219,47,77,162,139,224,206,116,253,70,165,201,223,68,119,248,114,56,74,37,60,195,112,28,9,68,248,160,69,179,174,32,226,251,194,109,219,144,225,216,214,134,161,182,203'],
        expectedOutput: '0xe24e91f2,0x7e5566b4,0xf9c4449a,0x4dbe1098'
      },
      {
        input: ['24,174,61,80,248,98,141,187,210,169,196,22,161,100,91,84,18,123,54,13,62,163,232,206,132,192,165,11,98,91,214,122,9,19,203,1,118,88,188,72,1,129,95,163,229,186,247,248,54,46,5,116,209,238,66,86,174,231,97,16,66,55,139,75'],
        expectedOutput: '0x5ac7e2df,0x6ca0d9cd,0xf04c1705,0x4bce8f21'
      },
      {
        input: ['74,86,76,192,174,9,9,175,138,104,82,111,34,74,103,88,120,109,204,73,91,15,159,9,246,0,26,57,55,165,132,130,251,209,66,169,218,75,88,100,179,171,211,214,245,59,46,109,168,251,182,3,10,86,12,0,86,38,57,142,203,190,16,198'],
        expectedOutput: '0xde74aaa8,0xf247a96c,0xc479b099,0xaedb8604'
      },
      {
        input: ['143,82,111,105,158,200,205,81,115,160,39,104,219,86,213,131,81,139,134,91,225,147,91,56,185,149,198,133,83,214,75,226,40,187,75,198,131,24,24,246,184,63,94,148,149,51,23,230,190,158,65,160,49,157,216,234,50,158,111,133,116,187,103,156'],
        expectedOutput: '0xede635a0,0x3b19d0c1,0xf3d629e4,0xd6c4b87c'
      },
      {
        input: ['118,178,99,249,202,123,239,130,186,77,22,80,128,46,54,62,204,120,222,253,21,182,231,71,84,87,204,200,18,51,101,136,229,200,129,175,67,112,49,253,189,72,77,61,118,132,123,66,252,90,63,17,16,38,88,101,125,36,45,143,87,146,23,60'],
        expectedOutput: '0x6a8b4a37,0x27d8ed9f,0xe54fc4e4,0x89260296'
      },
      {
        input: ['90,152,235,157,8,28,155,197,100,232,2,218,108,126,28,104,216,91,121,232,130,209,77,255,245,123,143,76,13,166,136,104,63,115,5,71,144,160,13,244,137,15,207,245,141,235,94,101,71,215,78,201,169,155,200,158,22,87,235,36,254,115,140,61'],
        expectedOutput: '0x2e2ccb11,0xe9e9b253,0x7131244e,0x6f45aa35'
      },
      {
        input: ['231,145,132,119,50,145,107,187,161,58,176,46,38,14,148,109,230,226,54,143,125,254,45,148,86,24,184,84,140,68,145,115,213,21,234,7,167,85,194,72,144,115,118,182,129,10,35,103,236,89,246,106,87,36,254,173,60,182,1,200,250,146,59,207'],
        expectedOutput: '0xb6814887,0xb1129aa5,0x809a6174,0xfe54346e'
      },
      {
        input: ['168,37,215,79,123,153,151,11,12,13,193,142,24,228,245,4,61,236,110,148,16,108,66,76,34,67,21,28,214,80,236,126,118,195,205,241,92,100,252,105,113,189,247,137,161,236,142,222,216,252,114,232,105,180,53,139,248,74,168,206,154,148,76,16'],
        expectedOutput: '0x7d6a4798,0x7ed8d814,0xc9161f1b,0x64dd6291'
      },
      {
        input: ['87,25,1,179,125,253,28,238,186,19,120,91,0,6,57,216,2,172,193,107,96,246,247,88,64,159,38,218,51,114,235,138,139,236,61,8,234,90,247,164,109,111,0,109,117,57,70,119,229,7,227,70,253,218,158,61,121,197,23,172,55,2,54,195'],
        expectedOutput: '0xe7f82fb0,0x848cc42a,0x90a92f1d,0x1f1fe823'
      },
      {
        input: ['239,115,203,217,205,194,125,59,49,125,168,166,183,238,30,156,245,1,226,242,219,129,47,84,70,71,0,125,73,54,64,56,169,12,17,119,206,143,178,0,12,90,166,195,73,196,96,62,197,66,49,160,195,96,244,9,167,244,135,241,42,199,41,212'],
        expectedOutput: '0x868feaae,0x2e9a2d7f,0x2e4c3a25,0xab4edede'
      },
      {
        input: ['211,59,75,162,202,253,162,214,87,72,154,160,13,250,223,210,60,16,115,0,112,103,9,24,92,144,9,134,88,50,90,43,109,165,205,55,162,111,14,250,184,168,154,197,162,121,151,222,137,10,222,250,114,232,18,206,120,27,84,208,77,175,252,187'],
        expectedOutput: '0xb8a7bb11,0xddca898e,0xd8f2a39b,0x51467c28'
      },
      {
        input: ['84,201,242,247,57,0,241,241,168,139,182,74,5,77,41,142,88,7,136,202,239,154,152,104,181,236,56,3,155,52,190,240,254,176,231,55,177,216,40,89,99,222,164,104,43,205,247,131,212,127,77,196,26,229,44,207,210,100,210,109,153,144,93,151'],
        expectedOutput: '0xe438c7ca,0x68f75b9d,0x5029c6ed,0x5887409e'
      },
      {
        input: ['65,68,206,242,28,246,75,128,212,239,232,255,188,223,131,145,95,208,85,121,182,129,72,136,229,27,245,126,171,83,21,236,151,227,222,180,217,42,52,173,25,28,173,214,252,48,103,91,0,188,212,182,61,28,62,34,55,52,161,227,135,182,207,30'],
        expectedOutput: '0x9f8a1e62,0x8b136cd9,0xffc11612,0x98223ab9'
      },
      {
        input: ['154,174,210,115,216,6,33,241,35,206,199,31,254,46,122,254,234,78,181,39,106,243,74,162,39,235,133,174,161,84,205,59,2,159,175,218,166,208,204,201,158,147,232,156,194,98,154,172,176,79,212,26,67,30,188,106,9,65,25,170,150,230,230,152'],
        expectedOutput: '0x58cc5e5c,0xdd1ca897,0x9e01cfac,0x5389664f'
      },
      {
        input: ['133,149,115,43,101,63,244,3,210,220,159,148,62,57,65,238,137,21,9,204,51,197,54,60,7,79,230,157,53,204,53,187,97,168,230,198,231,219,201,186,183,104,78,246,162,143,228,43,164,237,247,215,179,45,19,186,125,250,87,178,198,140,109,40'],
        expectedOutput: '0x066553fe,0xa96f38e1,0x3c6d38d2,0xf766e334'
      },
      {
        input: ['53,84,238,28,47,184,214,230,32,37,220,194,180,193,237,89,174,228,48,97,18,68,27,143,62,114,65,4,255,175,44,52,3,27,80,50,211,39,24,243,76,245,182,0,182,163,89,100,136,138,198,154,206,225,41,12,84,106,16,83,25,61,135,28'],
        expectedOutput: '0xac36c498,0x5deb52e4,0xce78d1d8,0x9cf0a585'
      },
      {
        input: ['88,215,78,43,254,103,30,74,92,212,75,18,120,164,118,0,46,60,154,252,30,195,8,114,45,25,197,71,86,76,99,174,35,178,217,34,25,247,108,117,204,183,135,68,92,253,68,138,58,222,135,88,161,143,202,206,168,143,21,254,219,121,172,254'],
        expectedOutput: '0xba920b00,0x50829588,0x3c91a007,0x16997d9b'
      },
      {
        input: ['43,133,32,68,125,141,185,73,68,64,141,160,61,209,43,119,175,178,207,80,65,153,30,234,40,52,232,3,173,149,2,216,26,34,28,151,175,213,224,244,21,109,148,82,62,191,202,237,113,153,61,179,51,92,157,91,144,133,95,61,26,97,21,53'],
        expectedOutput: '0x08adc2bd,0x929a8634,0x813dd713,0x662bdc0f'
      },
      {
        input: ['131,49,204,51,6,173,39,27,26,187,109,89,123,55,70,236,209,132,159,4,224,60,95,112,194,190,173,220,31,194,17,163,243,222,214,249,139,253,20,165,184,129,254,51,185,69,32,138,201,191,142,169,252,237,25,190,172,198,154,203,136,172,110,123'],
        expectedOutput: '0x6b7c0942,0xb2dcd6f0,0x5080a254,0xdc792db3'
      },
      {
        input: ['138,68,116,21,65,136,186,250,9,185,45,194,254,77,76,199,13,218,112,9,200,137,199,116,79,97,63,215,13,174,82,151,242,198,172,52,78,103,46,87,32,91,26,30,169,102,229,182,65,85,191,9,222,134,125,45,231,188,4,245,106,86,140,93'],
        expectedOutput: '0x1ef224af,0xda0b95c6,0x38cfd2fc,0x37cf0b78'
      },
      {
        input: ['28,57,145,106,160,191,193,192,26,219,222,195,66,195,121,131,24,56,140,246,190,9,35,166,197,39,155,48,125,39,141,153,96,30,3,0,221,196,192,247,160,158,187,226,97,52,101,121,109,241,111,43,250,146,209,191,185,108,239,54,148,124,207,244'],
        expectedOutput: '0x0046cceb,0xe2fb94a8,0xda85d731,0x93ef3893'
      },
      {
        input: ['154,210,245,119,151,181,111,55,84,42,25,181,94,126,47,203,111,158,247,105,49,200,40,234,53,24,33,201,148,240,189,47,195,178,166,90,104,21,145,188,63,170,113,158,40,160,105,151,63,96,0,112,41,40,90,94,64,123,39,213,108,228,4,47'],
        expectedOutput: '0x89664c05,0xc33d8a2a,0xd21dc854,0x0387d462'
      },
      {
        input: ['151,170,137,255,192,26,187,255,196,44,157,236,205,7,131,12,103,131,124,144,171,214,238,236,82,21,193,190,250,197,237,145,111,118,144,47,144,75,47,84,119,204,64,68,211,195,80,59,70,204,203,241,163,186,221,245,207,158,179,201,99,160,90,211'],
        expectedOutput: '0x3cd84157,0xd287aa91,0xb3d472c6,0x3e84b99c'
      },
      {
        input: ['22,234,2,166,53,49,250,173,254,58,241,209,253,66,12,67,14,216,52,177,146,18,166,97,176,89,43,20,249,133,231,15,112,233,181,165,27,175,82,25,233,68,234,230,134,247,41,148,207,94,70,97,112,236,194,32,70,237,52,63,115,27,79,227'],
        expectedOutput: '0x9dfd3ec7,0xb596b2ab,0x4711eb36,0x42be9d91'
      },
      {
        input: ['5,4,136,32,180,219,57,157,31,35,132,165,26,173,57,233,11,127,74,123,108,13,156,178,250,208,241,109,236,64,80,241,69,217,17,249,180,74,150,211,109,26,120,136,200,177,113,211,49,188,79,157,201,235,79,195,187,64,49,167,129,129,152,198'],
        expectedOutput: '0x2f1c9753,0xe1ce808f,0x0d5d4d85,0x1d0a686b'
      },
      {
        input: ['90,169,191,14,243,85,225,97,112,89,233,56,11,90,11,60,22,90,217,223,69,40,163,1,104,212,168,233,85,65,175,176,234,110,190,222,196,160,63,52,249,40,108,4,130,119,64,153,210,25,120,23,65,27,24,170,239,193,147,69,2,67,245,236'],
        expectedOutput: '0x8eee6af4,0xaa2a9cd7,0x170891ca,0xb29d8aa8'
      },
      {
        input: ['177,179,202,117,83,9,169,77,49,21,81,180,141,146,77,95,171,197,118,237,225,143,151,208,80,42,21,82,109,10,62,31,190,9,148,17,18,62,94,68,83,176,248,224,66,69,63,237,10,182,218,235,69,113,188,149,156,209,231,9,220,37,40,154'],
        expectedOutput: '0xee037bbb,0x837271e2,0x9e85be4a,0xdb079da9'
      },
      {
        input: ['46,189,171,65,251,10,133,78,186,125,47,252,194,110,233,204,36,196,184,105,53,116,254,209,69,229,219,33,11,3,187,57,192,103,122,187,113,255,10,43,124,57,39,62,167,16,11,204,212,195,53,10,55,52,219,124,25,182,158,36,186,89,94,122'],
        expectedOutput: '0x66b78de5,0x3f67ae09,0xd37a1337,0x2b971cf5'
      },
      {
        input: ['192,216,54,49,216,64,92,84,121,131,147,32,148,158,236,104,97,34,114,152,86,78,20,111,4,178,148,190,12,242,57,204,202,111,254,162,175,90,247,40,222,138,72,114,40,53,218,137,87,77,33,173,155,53,28,159,232,176,94,244,162,151,192,109'],
        expectedOutput: '0x70056153,0xba305cd5,0x67e82c18,0xf1de41b7'
      },
      {
        input: ['6,190,15,181,25,6,221,247,144,37,105,184,90,67,65,177,144,98,94,43,152,123,203,128,43,41,116,206,192,52,59,198,243,74,123,12,81,88,3,225,125,108,154,216,175,219,137,64,62,232,107,214,99,54,86,142,95,202,92,31,254,151,229,241'],
        expectedOutput: '0x55d139a5,0x6bf9089b,0x691cb860,0x27548e95'
      },
      {
        input: ['226,96,253,51,184,0,20,54,108,174,14,28,138,151,92,200,127,199,158,226,254,244,113,93,190,205,125,188,101,98,174,71,195,171,122,123,172,142,177,24,61,191,52,199,87,144,143,214,88,45,185,86,33,42,179,223,247,48,155,92,147,73,163,86'],
        expectedOutput: '0x7a4f9d31,0xbaa9b6ca,0x83ab7e12,0x724361e3'
      },
      {
        input: ['245,29,209,161,172,131,185,233,66,238,176,153,126,63,112,214,108,41,44,141,83,224,108,74,16,7,167,163,81,74,249,70,104,203,231,20,78,160,253,144,142,173,42,13,236,154,227,88,195,16,229,22,240,81,96,0,88,7,164,169,82,157,239,186'],
        expectedOutput: '0x6a2dc617,0x677755ae,0xd12c436d,0x7d05ea33'
      },
      {
        input: ['104,214,206,182,119,203,71,5,120,113,18,100,11,246,188,206,6,161,228,246,242,68,246,74,76,154,244,158,56,227,88,160,186,38,87,49,241,158,54,105,15,73,205,26,63,137,232,69,42,204,59,28,16,49,102,92,204,90,250,4,62,82,164,248'],
        expectedOutput: '0xe2a94e8c,0x00b37cb7,0xd407a425,0x4ddfc32c'
      },
      {
        input: ['120,251,41,105,153,95,210,168,168,159,194,231,40,170,44,82,118,103,110,135,153,213,227,101,47,222,105,109,48,13,101,169,9,142,18,162,238,229,75,150,132,13,126,173,184,170,255,46,18,110,181,171,67,153,16,114,119,121,224,167,134,69,80,143'],
        expectedOutput: '0x04fb2dfb,0x5a68c360,0xca11781a,0x61273a82'
      },
      {
        input: ['212,99,50,194,72,125,88,204,138,214,121,66,129,121,113,147,231,38,62,42,191,78,156,54,199,124,222,77,194,46,221,150,145,15,88,217,140,176,166,22,135,31,89,8,152,202,155,127,240,217,169,176,39,70,230,238,194,196,59,132,243,24,26,132'],
        expectedOutput: '0x0d99e996,0x18cd1af8,0xdd5836f3,0xbf29cc6a'
      },
      {
        input: ['39,114,94,179,35,4,202,170,35,35,178,188,237,77,59,221,38,229,141,77,43,116,59,237,56,118,114,43,143,140,176,182,255,14,106,34,18,52,204,53,87,126,241,68,203,45,33,241,18,175,62,61,35,121,42,91,239,156,135,126,41,55,53,40'],
        expectedOutput: '0x5b29d483,0x095da157,0xd57ff74b,0xe5c1754e'
      },
      {
        input: ['69,159,74,87,211,22,140,42,148,126,110,95,171,143,80,189,62,142,250,97,7,36,189,246,193,68,117,234,123,170,18,192,73,92,23,28,114,163,70,6,33,180,101,204,67,181,137,130,67,131,227,74,168,160,64,105,228,181,83,95,95,101,31,168'],
        expectedOutput: '0x9ed98789,0x454707ff,0xe93a0826,0x1b633078'
      },
      {
        input: ['193,54,196,51,218,10,57,251,190,158,200,2,83,81,132,150,213,103,224,125,8,32,230,236,214,57,76,53,158,107,222,95,162,162,146,124,173,203,119,107,105,63,109,188,145,241,82,102,89,50,227,97,82,201,77,40,2,153,94,160,5,60,255,167'],
        expectedOutput: '0x2739c567,0x45e25f8b,0x991a9f4b,0x05ad47af'
      },
      {
        input: ['222,145,35,139,92,154,247,197,218,100,129,107,86,211,209,175,5,180,16,87,125,93,128,127,247,222,31,252,26,30,163,248,175,198,132,11,96,123,208,58,223,81,165,53,36,118,228,41,42,244,128,167,82,0,38,73,222,69,69,248,99,232,241,18'],
        expectedOutput: '0xaa3a1af5,0xac5b5c31,0x1bc6f40d,0x9ea84c36'
      },
      {
        input: ['174,117,29,14,240,237,73,207,62,238,5,98,101,233,139,143,222,12,55,48,12,93,121,235,163,190,227,6,166,212,25,84,73,54,98,57,36,171,9,98,154,14,197,255,247,80,142,213,92,197,5,105,35,126,84,198,60,55,204,226,12,229,54,85'],
        expectedOutput: '0xf32d3a1e,0xeb1fd682,0x34aa89ab,0x130fe660'
      },
      {
        input: ['28,153,143,64,68,152,162,222,166,103,221,157,184,108,115,20,49,120,125,84,247,209,26,51,9,231,22,21,204,76,106,232,229,249,40,42,145,203,8,55,50,230,213,234,82,72,255,131,192,124,216,183,78,242,235,87,217,1,108,166,77,214,142,51'],
        expectedOutput: '0x03e11a05,0x6ccda3a9,0xb8b191b1,0x6b516e7e'
      },
      {
        input: ['208,183,93,97,130,101,153,180,75,110,159,157,182,158,33,118,26,249,46,104,235,25,191,197,26,43,107,103,2,249,154,210,176,247,51,50,93,204,231,168,58,134,70,240,36,103,103,62,96,149,167,75,174,102,16,200,146,123,47,148,117,202,102,37'],
        expectedOutput: '0xe0a71d7d,0xdf514cdd,0xf15c5c58,0x81e6cd41'
      },
      {
        input: ['193,153,88,30,102,63,199,160,197,13,145,233,116,248,39,212,141,206,31,59,53,48,3,199,171,50,91,32,252,193,70,190,90,158,220,192,221,163,97,162,176,242,139,36,234,178,248,119,129,24,178,182,72,181,125,243,231,216,20,228,153,90,162,243'],
        expectedOutput: '0x402a7250,0x35db2cda,0x1c7c2fbf,0xc5aa4147'
      },
      {
        input: ['248,126,180,213,34,21,119,210,7,2,247,241,180,239,104,53,7,26,235,79,207,104,67,182,64,87,154,217,177,60,205,169,187,129,126,221,150,245,175,157,247,166,142,171,150,246,225,157,16,204,237,223,53,48,149,117,135,48,79,56,108,28,225,39'],
        expectedOutput: '0x50b6d12f,0xccfe1d84,0x3ff92e3e,0xe4e601a4'
      },
      {
        input: ['157,95,4,51,84,180,208,75,90,94,246,240,84,215,142,100,164,123,67,217,171,216,78,50,8,157,106,117,185,75,156,86,170,161,137,254,85,89,73,175,183,63,160,11,23,46,111,187,169,178,148,84,139,226,134,147,128,240,8,57,59,165,144,229'],
        expectedOutput: '0x09079a57,0x66265db3,0x51150967,0xe4daaa1b'
      },
      {
        input: ['70,25,227,155,115,44,74,42,107,234,54,130,24,165,61,193,88,209,21,227,180,155,118,52,139,127,109,198,36,253,171,106,23,142,5,138,186,79,180,38,58,234,168,82,144,230,20,232,183,41,203,107,197,65,159,80,192,13,23,228,10,194,78,33'],
        expectedOutput: '0x059e815b,0x705296be,0x699c2a6f,0xb8fff528'
      },
      {
        input: ['81,83,171,11,163,96,49,221,74,218,47,218,192,67,194,119,109,141,227,50,207,130,130,143,143,153,116,154,92,194,187,173,22,103,184,185,199,234,150,17,196,197,236,132,9,174,251,118,60,222,168,11,97,42,154,240,196,14,138,32,209,70,205,231'],
        expectedOutput: '0x3a936f14,0x3eec1132,0x746cffff,0x83263b74'
      },
      {
        input: ['173,133,160,116,111,54,133,51,251,113,183,4,32,179,122,92,145,34,103,242,77,1,227,17,16,109,49,225,179,254,200,96,131,104,212,243,158,90,38,153,203,222,158,235,145,24,71,34,59,174,21,136,176,248,153,192,101,202,161,25,200,105,121,75'],
        expectedOutput: '0x6b79d586,0xa412332c,0xe9bb184f,0x54e477fc'
      },
      {
        input: ['209,78,62,111,168,101,8,115,67,166,95,212,191,166,246,250,85,11,130,5,3,27,197,105,229,102,130,173,207,251,248,160,73,55,15,241,156,23,101,223,190,196,179,125,106,169,119,191,181,249,196,184,20,137,33,249,239,163,166,190,159,158,94,232'],
        expectedOutput: '0x69661032,0xff303f3d,0x31945baa,0x8081182a'
      },
      {
        input: ['213,109,218,113,133,63,80,67,3,3,192,109,173,55,45,98,48,241,26,68,123,60,61,106,223,227,41,126,129,135,103,87,245,65,200,122,128,25,189,131,28,125,240,201,180,29,43,228,15,70,40,138,130,101,244,97,72,29,224,201,165,71,32,154'],
        expectedOutput: '0xe04f3d75,0xc0b9140d,0x3ad12ffd,0xa10c185d'
      },
      {
        input: ['136,233,20,8,2,209,139,30,78,123,232,2,153,19,230,168,89,14,50,219,115,38,61,187,68,29,132,233,100,165,131,236,142,151,244,144,104,127,174,182,250,150,184,147,170,158,59,3,172,109,223,31,148,28,218,216,57,94,193,157,3,68,137,145'],
        expectedOutput: '0xd539747b,0x222a0229,0xff1125f0,0x7158080b'
      },
      {
        input: ['219,125,33,67,252,208,249,246,102,177,138,16,79,197,20,251,51,243,26,199,15,244,159,72,82,96,229,86,164,110,231,127,235,9,194,231,217,187,221,63,108,103,80,187,45,100,182,96,87,208,39,102,196,198,174,22,38,147,108,202,1,84,73,236'],
        expectedOutput: '0x3cf0d885,0x0d300992,0xa0333405,0x45f3fec6'
      },
      {
        input: ['93,11,211,54,198,176,117,50,24,197,237,69,41,163,165,128,115,204,230,55,146,148,77,184,39,186,130,40,14,203,20,107,214,231,161,156,152,22,206,176,220,187,245,5,94,154,134,209,102,108,8,248,1,85,176,40,15,50,81,29,253,101,136,211'],
        expectedOutput: '0xa337fcbd,0xe7f7def1,0xeda4cbab,0xad090bc7'
      },
      {
        input: ['77,41,111,229,64,61,149,28,248,138,33,86,36,167,39,138,20,47,130,21,132,50,61,148,100,142,177,97,244,58,52,65,99,163,38,163,224,187,191,216,69,225,46,105,136,85,243,156,132,117,177,8,167,239,156,11,125,78,108,113,136,160,178,235'],
        expectedOutput: '0x3d7b24bd,0xe58ad18e,0xfd640e9d,0x1a008ff6'
      },
      {
        input: ['67,216,143,35,147,78,251,216,47,41,65,184,126,52,84,2,169,6,10,80,245,167,91,114,245,199,228,125,103,150,104,170,111,247,205,2,70,200,219,117,241,28,45,111,81,130,113,250,136,124,75,125,35,166,239,24,110,211,149,213,106,253,128,217'],
        expectedOutput: '0x97fa3eab,0x111bda46,0x66565bc0,0xe9f320da'
      },
      {
        input: ['245,77,219,59,22,182,176,7,211,222,119,36,96,232,30,232,100,105,101,135,16,84,159,126,40,52,83,146,50,211,107,39,33,70,98,55,253,18,62,208,240,181,244,80,158,18,56,2,124,157,138,140,242,41,10,26,94,93,172,144,49,23,183,82'],
        expectedOutput: '0xee0a4310,0xf75193ca,0x35c24e58,0x9483ed82'
      },
      {
        input: ['93,25,137,90,43,199,42,28,125,30,108,27,49,165,29,173,66,167,57,52,209,67,78,47,160,250,191,209,17,118,35,111,143,172,201,186,116,244,214,241,18,67,12,67,232,41,240,42,209,41,95,162,108,173,209,13,168,144,222,185,6,2,40,149'],
        expectedOutput: '0x8dbb2875,0x13d35697,0x39bf93e6,0x7ff49608'
      },
      {
        input: ['174,242,79,34,230,38,19,248,105,31,60,81,73,44,123,26,86,218,188,194,136,141,207,48,29,174,233,35,176,18,184,94,4,7,129,234,45,148,226,150,180,30,231,253,75,99,23,161,61,211,99,197,96,51,245,125,225,223,160,145,241,88,239,245'],
        expectedOutput: '0xaf8c6452,0x0a394f3a,0x265119cd,0x60602812'
      },
      {
        input: ['95,112,223,141,5,193,35,185,224,11,182,43,110,205,204,171,160,47,113,0,98,102,125,67,69,29,212,54,117,196,43,212,52,10,97,57,204,133,242,172,144,168,215,254,117,163,169,21,210,26,21,53,129,146,120,198,175,77,253,36,17,40,249,69'],
        expectedOutput: '0x3327bfab,0xc0d5b0bd,0xa90165c6,0x8ea16729'
      },
      {
        input: ['51,90,127,255,223,113,171,111,26,130,109,143,37,23,165,247,49,186,44,178,77,165,121,252,242,118,33,3,158,26,72,209,116,199,208,84,57,123,195,83,253,49,226,34,72,135,26,121,66,70,44,143,235,165,139,221,27,172,224,185,198,41,139,59'],
        expectedOutput: '0x8e0a9d66,0x5e39ecae,0x0959e43a,0x1144f36d'
      },
      {
        input: ['240,91,143,41,215,82,124,212,131,95,247,203,230,17,69,40,87,113,183,67,22,67,32,49,239,1,234,182,42,117,241,26,209,128,68,168,210,192,124,86,31,115,33,6,132,102,46,220,215,230,31,237,41,63,30,24,64,9,206,106,126,191,133,79'],
        expectedOutput: '0xafda6647,0xf7f9c0b4,0xd31dee40,0xd7637fd0'
      },
      {
        input: ['63,201,247,18,137,116,104,169,231,137,175,108,240,221,72,199,195,103,181,236,166,211,5,231,220,211,81,91,147,214,170,210,159,162,228,41,22,76,210,253,214,129,105,198,94,177,141,34,24,66,14,191,22,19,166,242,231,247,77,122,206,248,76,109'],
        expectedOutput: '0x14b209d9,0xf4ed60a1,0xa498bd92,0x933d5bf8'
      },
      {
        input: ['154,49,150,176,125,104,173,83,233,23,25,72,200,167,106,225,233,120,160,255,140,70,242,115,61,63,237,11,55,57,121,209,106,15,129,232,120,47,59,97,70,85,169,14,252,19,239,229,140,143,229,24,213,215,139,19,22,120,30,78,177,151,31,28'],
        expectedOutput: '0xdc73108a,0xfc0d2184,0x47ffd5e5,0x4efd65b4'
      },
      {
        input: ['167,161,4,31,208,63,128,22,148,42,36,144,61,20,118,201,163,91,225,121,50,108,140,72,228,170,150,150,66,182,178,233,87,182,8,39,245,136,61,138,178,97,26,240,117,144,185,25,235,155,146,29,7,30,102,236,200,252,130,10,178,52,243,9'],
        expectedOutput: '0x19955f35,0x0bdaf2f3,0x57b67589,0x3c0dd9dc'
      },
      {
        input: ['234,251,48,223,132,109,105,54,207,132,38,68,20,224,93,0,123,239,29,130,13,131,110,214,128,240,224,50,36,212,60,14,207,108,238,83,218,87,138,169,219,176,237,240,144,75,240,11,58,13,142,72,145,252,30,17,237,254,67,17,210,127,32,162'],
        expectedOutput: '0x9f8154c5,0x52aee962,0x689d0b19,0xbbff0445'
      },
      {
        input: ['236,14,245,198,101,127,111,65,48,92,49,192,167,33,204,226,46,90,42,191,86,72,208,67,70,20,85,25,147,117,187,127,131,176,69,232,48,180,41,96,17,90,32,184,123,236,154,170,70,196,105,157,12,58,224,83,78,53,108,225,170,39,97,45'],
        expectedOutput: '0x295ee902,0xfe4f6dbd,0xf84da29b,0xabdae70a'
      },
      {
        input: ['215,166,22,7,91,63,103,108,154,136,36,21,116,191,191,187,131,41,88,144,99,56,227,177,110,79,146,24,118,243,70,77,154,92,85,245,155,188,97,53,68,133,75,185,68,10,116,200,51,204,88,150,4,59,71,114,138,218,139,0,205,209,77,103'],
        expectedOutput: '0xa1c7fa91,0xaff89d1b,0xc4dae063,0xa802bdb7'
      },
      {
        input: ['45,162,92,200,95,189,254,163,67,73,92,135,83,208,79,135,156,167,29,161,226,101,19,108,63,158,108,12,111,186,116,156,92,208,101,187,142,99,95,209,172,187,88,255,140,168,134,40,79,164,201,50,9,221,158,72,123,11,84,235,197,200,135,33'],
        expectedOutput: '0x2672c645,0xfb4fd5d7,0x3d847d1d,0xe7ee3ff4'
      },
      {
        input: ['153,236,221,39,79,60,248,251,247,80,251,131,248,129,172,72,37,117,122,46,82,24,118,206,35,203,185,232,147,64,10,44,45,231,83,124,35,75,120,26,156,115,158,148,244,74,220,26,191,86,72,18,111,191,224,146,138,153,123,29,217,133,74,6'],
        expectedOutput: '0x87d17370,0x2674f11b,0x8a12c424,0xf26a56ef'
      },
      {
        input: ['108,157,131,143,233,251,169,133,110,71,25,98,145,246,124,81,76,197,99,187,132,67,78,14,220,201,43,181,78,117,188,186,19,63,73,252,58,242,129,168,58,154,10,203,144,135,28,221,76,127,152,208,194,230,222,158,175,9,84,253,127,16,183,146'],
        expectedOutput: '0x7147ec6a,0xedc3075c,0x3dabf2ec,0x5b396b53'
      },
      {
        input: ['79,0,142,137,243,15,49,45,169,59,248,58,194,21,23,14,148,175,222,87,150,188,245,69,198,73,67,69,89,250,215,168,251,101,49,238,116,98,27,29,158,19,87,96,40,110,111,189,30,77,20,180,10,9,249,208,83,60,21,172,55,236,85,50'],
        expectedOutput: '0xa029e412,0x5ffe41b8,0x0ef11070,0x96b3b505'
      },
      {
        input: ['81,134,32,197,233,59,226,135,78,58,231,119,168,86,52,198,164,72,122,174,81,116,126,164,176,147,81,231,127,166,25,208,44,57,149,21,116,119,156,195,177,132,58,90,218,110,32,126,182,155,44,7,15,170,172,191,61,253,167,188,163,192,140,207'],
        expectedOutput: '0xfd65d3c4,0x98f3cdb5,0x928880b1,0x3608db1f'
      },
      {
        input: ['250,33,229,110,153,129,49,74,5,107,164,224,217,197,94,143,96,139,151,111,53,67,46,115,64,213,47,227,150,188,178,144,221,151,254,118,25,48,193,30,155,101,254,117,42,93,4,138,232,155,249,29,222,40,144,30,253,192,1,147,124,180,35,89'],
        expectedOutput: '0x015b4d60,0x0c5e877d,0x78b6ef6b,0x1d824d71'
      },
      {
        input: ['75,34,208,100,82,145,131,237,246,129,98,33,222,103,171,198,2,165,228,225,205,116,255,202,52,1,94,176,181,129,10,0,163,218,101,245,107,232,227,97,105,69,130,72,172,46,14,175,211,242,144,160,103,143,106,155,144,200,76,69,74,86,70,237'],
        expectedOutput: '0xd98782d0,0x4645e21e,0x7b6d5ea2,0x5d63d302'
      },
      {
        input: ['48,171,227,155,147,198,252,252,11,127,68,184,173,83,103,128,69,247,32,172,134,138,72,23,83,148,92,157,234,162,138,26,77,109,181,224,51,177,221,63,48,33,247,221,116,94,93,186,85,125,102,219,8,174,242,91,66,79,248,44,241,130,70,63'],
        expectedOutput: '0x02fe229e,0x91073266,0xe871ed08,0x1c3eae1b'
      },
      {
        input: ['240,251,31,35,173,252,98,221,30,89,187,146,183,24,76,12,150,179,232,158,97,218,249,164,41,241,208,27,115,23,90,99,18,121,135,191,118,233,157,148,67,88,38,250,112,115,7,6,38,239,164,135,201,157,43,243,142,252,14,2,19,104,101,37'],
        expectedOutput: '0xeaebdaa5,0xd8695888,0xa357b2d5,0x93f4c67d'
      },
      {
        input: ['225,236,229,87,214,130,235,25,218,18,19,74,133,26,81,171,9,245,50,211,147,94,198,33,90,212,35,109,60,137,146,29,117,119,117,75,249,96,100,211,114,120,30,247,146,111,162,156,100,213,111,247,51,53,25,141,9,60,250,69,197,140,98,59'],
        expectedOutput: '0x15880878,0x0f98d660,0x18942f9a,0x66274250'
      },
      {
        input: ['4,215,134,253,56,235,209,170,99,239,162,245,94,68,145,194,25,0,186,76,53,211,217,62,15,211,131,213,96,230,16,100,189,150,97,245,129,50,160,228,33,66,218,127,134,107,66,160,108,252,236,161,207,198,224,222,153,99,179,249,73,195,93,7'],
        expectedOutput: '0xab73ac28,0x3d5f28e5,0x20cfa42a,0xb0460b94'
      },
      {
        input: ['90,191,252,219,241,156,192,19,222,154,146,101,5,212,5,113,208,241,19,159,183,243,126,81,86,49,74,160,245,168,167,79,103,163,42,88,64,234,107,30,132,254,131,138,210,136,251,163,122,14,66,49,1,192,130,88,242,205,248,231,117,159,54,220'],
        expectedOutput: '0xf26eefcb,0x0e8debea,0xa6f4e9d9,0xc75dbb70'
      },
      {
        input: ['66,96,52,130,75,160,161,207,158,36,89,112,173,85,19,39,99,86,88,101,22,219,189,8,168,181,239,29,84,37,249,150,134,45,25,209,205,186,160,107,222,250,220,139,79,239,178,178,69,11,23,92,230,212,100,142,137,84,171,221,121,164,116,255'],
        expectedOutput: '0xe63948c8,0x588fb2d3,0x89928872,0x1a1a3268'
      },
      {
        input: ['209,141,208,159,71,113,10,37,107,230,177,186,214,99,108,27,110,132,119,84,88,220,226,226,48,141,191,169,49,51,169,3,192,121,162,7,234,172,45,85,147,222,15,105,65,124,132,176,0,252,4,88,216,231,58,8,116,250,177,166,45,90,169,238'],
        expectedOutput: '0x02ac7246,0x8b5dc029,0x82a78263,0x12722019'
      },
      {
        input: ['212,75,245,190,247,34,20,138,0,35,243,66,159,120,242,159,116,246,248,76,221,50,84,82,44,5,248,90,96,161,72,52,236,61,242,227,96,6,110,96,42,97,162,201,217,148,105,77,139,97,153,104,147,237,186,192,243,178,26,83,83,98,135,63'],
        expectedOutput: '0x9933a664,0xac89a23c,0x547b0a32,0x8480cf83'
      },
      {
        input: ['159,121,35,255,128,145,96,170,242,2,115,204,151,220,25,34,61,179,138,209,160,69,145,147,247,171,230,75,13,109,138,172,231,173,172,103,62,12,17,49,14,132,253,165,97,22,199,158,201,82,111,106,151,0,253,142,171,228,217,184,81,100,101,56'],
        expectedOutput: '0xffed7d2d,0x1edc7fd9,0x75185717,0xacac28c7'
      },
      {
        input: ['17,17,159,80,29,176,129,43,53,126,209,150,148,152,52,94,234,164,200,129,164,197,16,80,169,233,8,251,77,109,51,95,126,211,175,155,131,48,199,184,174,152,78,66,48,131,160,27,39,104,156,203,46,172,27,215,150,36,210,227,145,6,66,16'],
        expectedOutput: '0x3cf206df,0x4d604e6e,0x1f7455d6,0x20e29b26'
      },
      {
        input: ['217,241,171,92,33,114,21,207,10,99,18,59,230,178,86,13,27,242,217,73,159,244,32,53,24,243,24,170,249,91,186,210,76,101,46,110,216,67,61,226,167,79,29,141,2,115,155,29,102,116,102,5,104,134,58,129,121,82,43,114,173,229,68,250'],
        expectedOutput: '0x19d7c8c0,0x8239ae05,0x8acc52d5,0x4f6d69ee'
      },
      {
        input: ['74,115,104,34,182,165,5,93,245,34,235,247,150,134,20,252,250,122,1,98,0,59,227,122,141,14,236,59,243,49,53,62,164,157,96,90,66,101,184,55,136,163,46,30,41,66,26,35,188,27,133,189,86,105,55,227,119,35,30,107,84,83,169,248'],
        expectedOutput: '0x68aeea60,0x67dd2f67,0xdda51b3e,0x1488fa6b'
      },
      {
        input: ['240,9,83,51,111,11,106,247,174,153,21,215,219,47,250,152,74,127,85,160,232,140,131,96,175,162,203,4,245,116,252,230,125,79,25,236,90,131,227,8,28,248,223,248,39,217,144,113,89,229,17,65,113,149,161,32,55,108,36,44,224,33,18,94'],
        expectedOutput: '0xe487dc34,0x3f8a8091,0x03531a7e,0xdbabdb42'
      },
      {
        input: ['112,43,74,203,175,46,211,203,38,179,195,78,140,83,191,229,56,209,39,169,102,200,202,157,53,238,201,21,15,220,115,128,7,190,75,182,236,30,130,18,209,69,96,94,153,32,67,209,241,106,123,87,51,69,244,104,51,189,125,67,153,241,195,161'],
        expectedOutput: '0x232f3172,0x42242a3d,0xb1a122ee,0xea068f0a'
      },
      {
        input: ['175,14,87,155,44,217,173,254,31,14,92,184,46,159,137,31,10,4,118,61,73,106,165,125,39,34,192,193,19,131,98,194,145,185,93,189,147,11,187,178,25,23,106,71,183,243,102,193,248,220,254,65,70,163,190,109,197,126,46,217,1,144,155,146'],
        expectedOutput: '0xa3d59e1a,0xaba37fc9,0xca21588d,0x9982ae51'
      },
      {
        input: ['74,249,80,221,4,11,143,29,35,249,100,218,236,202,155,228,166,153,38,236,60,228,89,1,99,136,218,100,24,118,247,98,111,71,63,115,82,206,144,117,199,244,79,180,190,234,152,100,131,190,80,191,163,169,193,6,49,155,106,74,17,97,172,128'],
        expectedOutput: '0xd3d6d510,0x62b3df78,0xdb7425b3,0x15aed0c8'
      },
      {
        input: ['168,236,243,251,186,131,112,130,119,192,54,53,170,206,153,46,141,233,237,48,147,174,54,196,74,160,14,91,2,187,220,170,167,207,165,97,83,22,227,202,214,25,0,128,232,153,174,117,131,156,165,22,74,219,218,148,123,233,240,125,164,204,40,75'],
        expectedOutput: '0x00e86124,0xe1c2638a,0x0f2a6ced,0xcdae8622'
      },
      {
        input: ['155,205,172,238,227,144,185,185,169,185,58,145,82,232,6,213,132,171,235,207,134,198,99,2,175,83,127,83,31,167,158,187,117,74,169,88,218,98,18,132,27,76,21,110,52,28,67,185,199,47,136,78,245,235,80,164,63,207,247,94,119,149,25,236'],
        expectedOutput: '0xe0aebdb6,0xd41e5a84,0x426d924e,0x654d6a82'
      },
      {
        input: ['223,195,68,186,37,86,62,65,162,83,175,215,111,242,144,55,33,24,133,22,3,213,186,66,164,177,161,27,70,186,7,38,125,76,224,163,162,30,228,69,113,147,28,225,133,172,24,167,196,157,189,199,114,120,10,22,41,171,50,112,101,57,150,227'],
        expectedOutput: '0xbc716de5,0x5f551671,0x2ad58ddd,0x02a235f3'
      },
      {
        input: ['133,118,134,40,148,106,109,5,253,137,230,130,53,254,41,249,155,231,192,13,95,202,36,136,117,86,248,219,143,142,190,21,4,68,61,152,174,170,158,171,51,132,45,104,131,87,97,30,62,33,44,157,236,80,37,97,166,30,60,53,172,250,74,177'],
        expectedOutput: '0x2f0505e3,0x861797f8,0x9fa6a227,0x42ab99d7'
      },
      {
        input: ['62,135,73,236,49,231,151,100,108,197,204,239,28,45,13,90,79,57,247,59,137,28,156,47,58,217,101,231,211,175,152,18,55,225,254,104,201,150,205,53,91,153,36,119,199,49,209,22,107,200,81,244,228,237,36,31,198,137,6,154,56,158,172,111'],
        expectedOutput: '0xe0b53bf9,0xe1015410,0xdc10884c,0xc5714a55'
      },
      {
        input: ['127,170,216,72,64,165,125,155,62,161,18,5,211,227,27,62,171,108,50,144,90,86,175,32,223,181,186,24,83,102,135,210,17,95,27,81,4,152,237,67,58,255,72,13,227,100,75,142,208,125,30,42,212,205,75,179,130,5,203,213,108,83,168,125'],
        expectedOutput: '0x9a39d70a,0x4e7d0c7a,0x3266232f,0x0efc9351'
      },
      {
        input: ['178,195,206,183,91,187,250,149,187,66,162,158,166,237,44,119,107,75,161,63,24,236,242,155,242,190,112,94,17,24,219,195,219,169,122,55,101,116,204,32,183,111,190,93,92,234,212,199,53,118,6,78,98,249,233,84,183,89,178,200,114,141,139,77'],
        expectedOutput: '0xe00b2a42,0xc5d96001,0x55249f0e,0x8621ca16'
      },
      {
        input: ['55,6,132,156,122,81,188,49,192,122,143,28,100,99,228,154,217,234,232,60,227,209,144,154,42,67,98,156,208,238,234,7,244,110,163,110,191,95,160,127,217,47,156,62,146,128,216,108,106,192,168,78,145,56,232,187,123,75,88,76,57,66,83,45'],
        expectedOutput: '0xf42965b9,0xc4b70818,0x59c5fde9,0xaeacade3'
      },
    ],
    testFunction: function(i) {
      const md = new MD5();
      const buf = i[0].split(',').map((q) => Number.parseInt(q, 10));
      md.byteArrayCopy(md.context.buffer, 0, buf, 0, 64);
      md.transform();
      return MD5.prototype.dwordToHex(md.context.state[0]) + ',' +
             MD5.prototype.dwordToHex(md.context.state[1]) + ',' +
             MD5.prototype.dwordToHex(md.context.state[2]) + ',' +
             MD5.prototype.dwordToHex(md.context.state[3]);
    }
  },

  {
    desc: 'MD5("") == d41d8cd98f00b204e9800998ecf8427e',
    testFunction: function() { return md5(''); },
    expectedResult: 'd41d8cd98f00b204e9800998ecf8427e',
  },
  {
    desc: 'MD5("a") == 0cc175b9c0f1b6a831c399e269772661',
    testFunction: function() { return md5('a'); },
    expectedResult: '0cc175b9c0f1b6a831c399e269772661',
  },
  {
    desc: 'MD5("abc") == 900150983cd24fb0d6963f7d28e17f72',
    testFunction: function() { return md5('abc'); },
    expectedResult: '900150983cd24fb0d6963f7d28e17f72',
  },
  {
    desc: 'MD5("message digest") == f96b697d7cb7938d525a2f31aaf161d0',
    testFunction: function() { return md5('message digest'); },
    expectedResult: 'f96b697d7cb7938d525a2f31aaf161d0',
  },
  {
    desc: 'MD5("abcdefghijklmnopqrstuvwxyz") == c3fcd3d76192e4007dfb496cca67e13b',
    testFunction: function() { return md5('abcdefghijklmnopqrstuvwxyz'); },
    expectedResult: 'c3fcd3d76192e4007dfb496cca67e13b',
  },
  {
    desc: 'MD5("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") ' +
          '== d174ab98d277d9f5a5611c2c9f419d9f',
    testFunction: function() {
      return md5('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789');
    },
    expectedResult: 'd174ab98d277d9f5a5611c2c9f419d9f',
  },
  {
    desc: 'MD5("123456789012345678901234567890123456789012345678901234567890123456' +
          '78901234567890") == 57edf4a22be3c955ac49da2e2107b67a',
    testFunction: function() {
      return md5('12345678901234567890123456789012345678901234567890123456' +
                 '789012345678901234567890');
    },
    expectedResult: '57edf4a22be3c955ac49da2e2107b67a',
  },
];
