const quicktestTests = [
  {
    desc: 'Test result matching expected result should pass',
    testFunction: function() { return 12; },
    expectedResult: 12,
  },
  {
    desc: 'Test result not matching expected result should fail',
    testFunction: function() { return 'orange'; },
    expectedResult: 12
  },
  {
    desc: 'Error being thrown when no throwable expected should fail',
    testFunction: function() {throw new Error('some error');},
    expectedResult: 12
  },
  {
    desc: 'Wrong error type being thrown (a different error is expected) should fail',
    testFunction: function() {throw new RangeError('some range error');},
    expectedError: TypeError
  },
  {
    desc: 'Expected error type being thrown should pass',
    testFunction: function() { throw new TypeError('some type error'); },
    expectedError: TypeError
  },
  {
    desc: 'Expected error type being thrown, ' +
          'and observed message beginning with expected message, should pass',
    testFunction: function() {
      throw new TypeError('some type error longer than expected');
    },
    expectedError: new TypeError('some type error')
  },
  {
    desc: 'Expected error type being thrown, ' +
          'but observed message does not start with expected message, should fail',
    testFunction: function() { throw new TypeError('some type error'); },
    expectedError: new TypeError('rogue message')
  },
  {
    desc: 'Wrong error type being thrown, but has an expected message prefix, should fail',
    testFunction: function() {
      throw new TypeError('some type error longer than expected');
    },
    expectedError: new RangeError('some type error')
  }
];
