/**
 * @file utils.test.ts
 * @brief Unit tests for utility functions
 * @details Tests date formatting and utility functions
 * @date 2024-12-19T00:00:00Z
 * @author Forum System
 */
define(["require", "exports", "../src/utils"], function (require, exports, utils_1) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    /**
     * @brief Test formatDate function
     */
    function testFormatDate() {
        // Test with a known timestamp
        var timestamp = 1609459200; // 2021-01-01 00:00:00 UTC
        var formatted = (0, utils_1.formatDate)(timestamp);
        // Should be in "YYYY-MM-DD HH:mm:ss TIMEZONE" format
        var regex = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} .+$/;
        if (!regex.test(formatted)) {
            throw new Error('Date format is not "YYYY-MM-DD HH:mm:ss TIMEZONE"');
        }
        console.log('✓ formatDate test passed');
    }
    /**
     * @brief Run all tests
     */
    function runTests() {
        var passed = 0;
        var failed = 0;
        var tests = [
            { name: 'formatDate', fn: testFormatDate }
        ];
        tests.forEach(function (test) {
            try {
                test.fn();
                passed++;
            }
            catch (error) {
                console.error('✗ ' + test.name + ': ' + (error.message || 'Test failed'));
                failed++;
            }
        });
        console.log('\nPassed: ' + passed);
        console.log('Failed: ' + failed);
        if (failed > 0) {
            throw new Error('Some tests failed');
        }
    }
    // Run tests if this file is executed directly
    if (typeof window === 'undefined') {
        runTests();
    }
});
