/**
 * @typedef {[{input: [*], expectedOutput: *}]} DataProvider
 * @typedef {{desc:String,testFunction:Function<>,expectedResult:*}} TestSingleExpectResult
 * @typedef {{desc:String,testFunction:Function<>,expectedError:Error}} TestSingleExpectThrow
 * @typedef {{desc:String,
 *     testFunction:Function<[*]>,
 *     dataProvider: DataProvider
 * }} TestWithProvider
 *
 * @typedef {TestSingleExpectResult|TestSingleExpectThrow} TestSingle
 * @typedef {TestSingle|TestWithProvider} Test
 *
 * @param {[Test]} tests
 * @constructor
 */

const QuickTestIterator = function* (tests) {

  /**
   * @param {Test} test
   * @param {[*]} input
   * @return {{testPassed: boolean,
   * testDiagnosis: *,
   * observedResult: *,
   * thrownError: *,
   * testDurationInMilliseconds: (number)}}
   */
  function runTest(test, input) {
    let observedResult;
    let thrownError;
    let testDurationInMilliseconds;
    let testPassed = false;
    let testDiagnosis;

    // Run the test
    let millisecondsBefore = window.performance.now();
    try {
      observedResult = test.testFunction(input);
    } catch (e) {
      thrownError = e;
    }
    let millisecondsAfter = window.performance.now();
    testDurationInMilliseconds = millisecondsAfter - millisecondsBefore;

    // what just happened?
    if ((typeof observedResult === 'undefined') && (typeof thrownError === 'undefined')) {
      // The function may have returned undefined, or not returned anything.
      if (test.hasOwnProperty('expectedResult') && typeof test.expectedResult === 'undefined') {
        testPassed = true;
      } else {
        testPassed = false;
        testDiagnosis = 'Test returned undefined.';
      }
    } else if ((typeof observedResult === 'undefined') && (typeof thrownError !== 'undefined')) {
      // An error was thrown
      if (typeof test.expectedError === 'undefined') {
        testPassed = false;
        testDiagnosis = 'Error of type ' + thrownError.name + ' thrown, but no error expected.';
      } else if (thrownError.name === test.expectedError.name) {
        if (typeof test.expectedError.message === 'undefined') {
          // The thrown error was of the correct type, and no further checks needed to be made.
          testPassed = true;
        } else {
          if (thrownError.message.startsWith(test.expectedError.message)) {
            testPassed = true;
          } else {
            testPassed = false;
            testDiagnosis = 'Correct error type was thrown, but error message was unexpected.';
          }
        }
      } else {
        testPassed = false;
        testDiagnosis =
            'Expected a ' + test.expectedError.name +
            ' to be thrown, but thrown error was of type ' + thrownError.name;
      }
    } else if ((typeof observedResult !== 'undefined') && (typeof thrownError === 'undefined')) {
      if (test.hasOwnProperty('expectedResult') && typeof test.expectedResult === 'undefined') {
        // The expected return type is the undefined type, but test method returned something else.
        // Special case of the next else branch below.
        testPassed = false;
        testDiagnosis =
            'Test returned type ' + (typeof observedResult) +
            ' but the undefined type was expected.';
      } else if (typeof observedResult !== typeof test.expectedResult) {
        testPassed = false;
        testDiagnosis = 'Test returned type ' + (typeof observedResult) +
                        ' but expected result is of type ' + (typeof test.expectedResult);
      } else if (observedResult !== test.expectedResult) {
        testPassed = false;
        testDiagnosis = 'Test return value was different from expected value.';
      } else {
        testPassed = true;
      }
    } else {
      // observed result and thrown error are both defined, which is an error with the test rig.
      throw new Error('Observed result and thrown error are both defined.');
    }
    return {testPassed, testDiagnosis, observedResult, thrownError, testDurationInMilliseconds};
  }

  for (let test of tests) {
    let result;

    if (test.hasOwnProperty('dataProvider')) {
      test.desc = '[' + test.dataProvider.length + ' tests] ' + test.desc;
      let rollingDuration = 0;
      for (let i = 0; i < test.dataProvider.length; i++) {
        test.expectedResult = test.dataProvider[i].expectedOutput;

        result = runTest(test, test.dataProvider[i].input);

        rollingDuration += result.testDurationInMilliseconds;
        result.testDurationInMilliseconds = rollingDuration;
        if (!result.testPassed) {
          result.testDiagnosis =
              '(Test ' + (i + 1) + ' of ' + test.dataProvider.length + '): ' + result.testDiagnosis;
          break;
        }
      }
    } else {
      result = runTest(test, undefined);
    }

    /**
     * @typedef {{testPassed:!boolean,testDiagnosis:?string,
     * testDescription:!string,
     * expectedResult:?*,observedResult:?*,expectedError:?Error,thrownError:?Error,
     * testDurationInMilliseconds:!number}} TestResult
     *
     * @type {TestResult}
     */
    yield {
      testPassed: result.testPassed,
      testDiagnosis: result.testDiagnosis,
      testDescription: test.desc,
      expectedResult: test.expectedResult,
      observedResult: result.observedResult,
      expectedError: test.expectedError,
      thrownError: result.thrownError,
      testDurationInMilliseconds: result.testDurationInMilliseconds
    };

  }
};
