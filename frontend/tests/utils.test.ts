/**
 * @file utils.test.ts
 * @brief Unit tests for utility functions
 * @details Tests date formatting and utility functions
 * @date 2024-12-19T00:00:00Z
 * @author Forum System
 */

import { formatDate } from '../src/utils';

/**
 * @brief Test formatDate function
 */
function testFormatDate(): void {
    // Test with a known timestamp
    const timestamp = 1609459200; // 2021-01-01 00:00:00 UTC
    const formatted = formatDate(timestamp);
    
    // Should be in "YYYY-MM-DD HH:mm:ss TIMEZONE" format
    const regex = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} .+$/;
    if (!regex.test(formatted)) {
        throw new Error('Date format is not "YYYY-MM-DD HH:mm:ss TIMEZONE"');
    }
    
    console.log('✓ formatDate test passed');
}

/**
 * @brief Run all tests
 */
function runTests(): void {
    let passed = 0;
    let failed = 0;
    
    const tests = [
        { name: 'formatDate', fn: testFormatDate }
    ];
    
    tests.forEach(function(test) {
        try {
            test.fn();
            passed++;
        } catch (error: any) {
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

