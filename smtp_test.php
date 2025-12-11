<?php
/**
 * WP Comment Notify - Standalone SMTP Test Script
 *
 * This script attempts to send an email using the plugin's saved SMTP settings,
 * bypassing the WordPress wp_mail function to get a clean test environment.
 *
 * @version 1.0
 */

// --- IMPORTANT ---
// For security, this script should be deleted from your server after testing is complete.
// To use, place this file in the root of the 'wp-comment-notify' plugin directory.
// Then, you need to figure out the correct path to your wp-load.php file.
// Common paths are: __DIR__ . '/../../../wp-load.php' (if plugin is in wp-content/plugins)
// Access it via your browser, e.g., https://your-site.com/wp-content/plugins/wp-comment-notify/smtp_test.php

// --- WordPress Bootstrap ---
define('WP_USE_THEMES', false);
$wp_load_path = realpath(__DIR__ . '/../../../wp-load.php');

if (!$wp_load_path || !file_exists($wp_load_path)) {
    // Fallback for different directory structures
    $wp_load_path = realpath(__DIR__ . '/../../wp-load.php');
    if (!$wp_load_path || !file_exists($wp_load_path)) {
        die("FATAL ERROR: Could not find wp-load.php. Please check the path in this script. Tried: " . realpath(__DIR__ . '/../../../wp-load.php') . " and " . realpath(__DIR__ . '/../../wp-load.php'));
    }
}
require_once($wp_load_path);

// --- PHPMailer Bootstrap ---
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

// WordPress includes PHPMailer. We just need to ensure the classes are available.
if (!class_exists(PHPMailer::class)) {
    require_once ABSPATH . WPINC . '/PHPMailer/PHPMailer.php';
    require_once ABSPATH . WPINC . '/PHPMailer/SMTP.php';
    require_once ABSPATH . WPINC . '/PHPMailer/Exception.php';
}

// --- Plugin Logic Bootstrap ---
$plugin_mail_file = __DIR__ . '/includes/WordPress_Mail.php';
if (!file_exists($plugin_mail_file)) {
    die("FATAL ERROR: Could not find includes/WordPress_Mail.php. Make sure this test script is in the 'wp-comment-notify' plugin root directory.");
}
require_once($plugin_mail_file);


// --- Test Execution ---
header('Content-Type: text/plain; charset=utf-8');
echo "==================================================\n";
echo "WP Comment Notify - Standalone SMTP Test Script\n";
echo "==================================================\n\n";
echo "Timestamp: " . gmdate('Y-m-d H:i:s') . " UTC\n\n";

try {
    // 1. Create a new PHPMailer instance for a clean test
    $mail = new PHPMailer(true);

    // 2. Enable verbose debug output to the browser
    echo "STEP 1: Enabling verbose SMTP debug output...\n";
    $mail->SMTPDebug = SMTP::DEBUG_SERVER;
    $mail->Debugoutput = function($str, $level) {
        // We use echo instead of a log file for direct browser feedback
        echo "DEBUG [$level]: " . htmlspecialchars($str) . "\n";
    };
    echo "--------------------------------------------------\n";

    // 3. Apply the exact same settings from your plugin's options
    echo "STEP 2: Applying saved settings via pcn_phpmailer_init()...\n";
    pcn_phpmailer_init($mail);
    
    $settings = get_option('pcn_smtp_settings', []);
    if (empty($settings['enable_smtp'])) {
        die("RESULT: FAILED\nREASON: SMTP is not enabled in the plugin settings. Test aborted.\n");
    }
    echo "Applied settings successfully.\n";
    echo "--------------------------------------------------\n";

    // 4. Set up the test email content
    echo "STEP 3: Configuring test email recipients and content...\n";
    
    // Recipient: Your site's admin email
    $recipient_email = get_bloginfo('admin_email');
    $mail->addAddress($recipient_email);

    // From address and name are set inside pcn_phpmailer_init based on your settings
    // We will just log what was set
    echo " - From Address (after init): " . htmlspecialchars($mail->From) . "\n";
    echo " - From Name (after init): " . htmlspecialchars($mail->FromName) . "\n";
    echo " - Recipient: " . htmlspecialchars($recipient_email) . "\n";

    // Email content
    $mail->isHTML(true);
    $mail->Subject = 'Standalone SMTP Test for WP Comment Notify';
    $mail->Body    = 'This is a test email sent directly via PHPMailer using your saved settings. If you received this, your settings are correct.';
    $mail->AltBody = 'This is a test email sent directly via PHPMailer using your saved settings.';
    echo "--------------------------------------------------\n";

    // 5. Send the email
    echo "STEP 4: Attempting to send the email...\n\n";
    $mail->send();

    echo "\n--------------------------------------------------\n";
    echo "RESULT: SUCCESS\n";
    echo "The email was successfully sent to " . htmlspecialchars($recipient_email) . ".\n";
    echo "Please check the inbox.\n";

} catch (Exception $e) {
    echo "\n--------------------------------------------------\n";
    echo "RESULT: FAILED\n";
    echo "An exception occurred. PHPMailer error message:\n";
    echo ">> " . $mail->ErrorInfo . "\n\n";
    echo "This indicates that even outside of WordPress's wp_mail() function, the connection to the SMTP server failed.\n";
    echo "The issue is very likely with the SMTP credentials, account status (locked, needs verification), or network/firewall, not the plugin code itself.\n";
}

echo "\n==================================================\n";
echo "Test finished. Remember to delete this file.\n";
echo "==================================================\n";

?>
