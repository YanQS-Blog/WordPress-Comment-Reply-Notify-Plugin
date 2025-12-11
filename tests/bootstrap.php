<?php
// Minimal bootstrap for PHPUnit tests.
if (! defined('ABSPATH')) {
    define('ABSPATH', __DIR__ . '/../');
}

// Provide a predictable salt for encryption tests
if (! function_exists('wp_salt')) {
    function wp_salt($suffix = '') {
        return 'unit_test_salt' . $suffix;
    }
}

// Provide minimal implementations of WordPress helper functions used by classes
if (! function_exists('sanitize_text_field')) {
    function sanitize_text_field($str) { return is_string($str) ? trim($str) : ''; }
}
if (! function_exists('sanitize_email')) {
    function sanitize_email($email) { return filter_var($email, FILTER_SANITIZE_EMAIL); }
}

// Load classes under test directly
require_once __DIR__ . '/../includes/class-pcn-settings.php';
