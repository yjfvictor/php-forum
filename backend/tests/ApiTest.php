<?php
/**
 * @file ApiTest.php
 * @brief Unit tests for the API endpoints
 * @details Tests all API functionality including authentication, threads, and user management
 * @date 2025-12-18
 * @author Victor Yeh
 */

require_once __DIR__ . '/../config.php';

/**
 * @brief Simple test framework
 */
class TestFramework {
    private $tests = [];
    private $passed = 0;
    private $failed = 0;
    
    public function test($name, $callback) {
        $this->tests[] = ['name' => $name, 'callback' => $callback];
    }
    
    public function assertTrue($condition, $message = '') {
        if (!$condition) {
            throw new Exception($message ?: 'Assertion failed');
        }
    }
    
    public function assertEquals($expected, $actual, $message = '') {
        if ($expected !== $actual) {
            throw new Exception($message ?: "Expected {$expected}, got {$actual}");
        }
    }
    
    public function run() {
        echo "Running tests...\n\n";
        foreach ($this->tests as $test) {
            try {
                $test['callback']($this);
                echo "✓ {$test['name']}\n";
                $this->passed++;
            } catch (Exception $e) {
                echo "✗ {$test['name']}: {$e->getMessage()}\n";
                $this->failed++;
            }
        }
        echo "\n";
        echo "Passed: {$this->passed}\n";
        echo "Failed: {$this->failed}\n";
        return $this->failed === 0;
    }
}

/**
 * @brief Mock session for testing
 */
function mockSession($username = null) {
    $_SESSION = [];
    if ($username) {
        $_SESSION['username'] = $username;
    }
}

/**
 * @brief Test credentials loading and saving
 */
function testCredentials() {
    $tf = new TestFramework();
    
    $tf->test('Load credentials returns array', function($tf) {
        $creds = loadCredentials();
        $tf->assertTrue(is_array($creds));
    });
    
    $tf->test('Save and load credentials', function($tf) {
        $testCreds = ['testuser' => ['password' => 'hash', 'isAdmin' => false]];
        saveCredentials($testCreds);
        $loaded = loadCredentials();
        $tf->assertTrue(isset($loaded['testuser']));
        // Clean up
        unset($loaded['testuser']);
        saveCredentials($loaded);
    });
    
    return $tf->run();
}

/**
 * @brief Test thread loading and saving
 */
function testThreads() {
    $tf = new TestFramework();
    
    $tf->test('Load threads returns array', function($tf) {
        $threads = loadThreads();
        $tf->assertTrue(is_array($threads));
    });
    
    $tf->test('Save and load threads', function($tf) {
        $testThreads = [
            [
                'id' => 1,
                'title' => 'Test Thread',
                'author' => 'testuser',
                'createdAt' => time(),
                'posts' => []
            ]
        ];
        saveThreads($testThreads);
        $loaded = loadThreads();
        $tf->assertTrue(count($loaded) > 0);
        $tf->assertEquals('Test Thread', $loaded[0]['title']);
        // Clean up
        saveThreads([]);
    });
    
    return $tf->run();
}

/**
 * @brief Test authentication functions
 */
function testAuth() {
    $tf = new TestFramework();
    
    $tf->test('isLoggedIn returns false when not logged in', function($tf) {
        mockSession();
        $tf->assertTrue(!isLoggedIn());
    });
    
    $tf->test('isLoggedIn returns true when logged in', function($tf) {
        mockSession('testuser');
        $tf->assertTrue(isLoggedIn());
    });
    
    $tf->test('getCurrentUsername returns null when not logged in', function($tf) {
        mockSession();
        $tf->assertEquals(null, getCurrentUsername());
    });
    
    $tf->test('getCurrentUsername returns username when logged in', function($tf) {
        mockSession('testuser');
        $tf->assertEquals('testuser', getCurrentUsername());
    });
    
    return $tf->run();
}

// Run all tests
echo "=== API Tests ===\n\n";

$allPassed = true;
$allPassed = testCredentials() && $allPassed;
$allPassed = testThreads() && $allPassed;
$allPassed = testAuth() && $allPassed;

echo "\n=== Test Summary ===\n";
if ($allPassed) {
    echo "All tests passed!\n";
    exit(0);
} else {
    echo "Some tests failed.\n";
    exit(1);
}

