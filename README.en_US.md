# Wordpress Comment & Reply Notify Plugin

[中文文档](README.md) | [English Documentation](README.en_US.md) | [中文Wiki](https://github.com/Yan-QS/WordPress-Comment-Reply-Notify-Plugin/wiki/Home) | [English Wiki](https://github.com/Yan-QS/WordPress-Comment-Reply-Notify-Plugin/wiki/Home.en_US)

> English localization is supported now.

![Plugin.gif](/Plugin.gif)

This is a simple yet powerful WordPress plugin designed to enhance and customize comment notification emails. It addresses the shortcomings of WordPress's default email functionality by providing reliable SMTP sending, editable HTML templates, and detailed debugging tools.

Plugin Homepage: [https://yanqs.me/wp-comment-notify-plugin/](https://yanqs.me/wp-comment-notify-plugin/)

## Key Features

- **Reliable SMTP Sending**:
  - Supports sending all comment notification emails via external SMTP servers (e.g., Gmail, Outlook, corporate email, etc.).
  - Customizable SMTP host, port, and encryption (None, SSL, TLS).
  - Supports SMTP authentication (Username/Password).

- **Flexible Sender Settings**:
  - Allows separating the SMTP login username from the "From Email" and "From Name".
  - Optional enforcement to unify the "From Email" and "Envelope Sender" as the SMTP username to improve email delivery rates.

- **Editable HTML Templates**:
  - Provides independent HTML email templates for "New Reply Notification", "Admin New Comment Notification", and "Pending Comment Notification".
  - Templates can be edited directly in the settings page, supporting HTML.

- **Powerful Admin Management**:
  - **Master Switch**: Enable or disable the entire plugin's email notification function with one click.
  - **Email Test**: After configuring SMTP, you can send a test email to a specified address to quickly verify the settings.
  - **Debug Logs**:
    - Real-time recording of detailed SMTP session logs (complete communication between client and server).
    - View the last N debug logs in the backend to quickly locate issues (such as `535 Login fail` authentication errors).
    - Supports one-click log clearing.

- **Advanced Compatibility Options**:
  - **Login Mechanism**: Choose between "Auto Negotiate", "LOGIN", and "PLAIN" SMTP authentication mechanisms to compatible with different service providers.
  - **Force IPv4 Connection**: Force IPv4 connection to the SMTP server when there are IPv6 connection issues in the server environment.

- **Template Editing Upgraded (TinyMCE)**:
  - The admin template editor now integrates TinyMCE, providing a richer WYSIWYG HTML editing experience with better formatting and paste handling.

- **One‑click Unsubscribe**:
  - Reply notification emails include a secure unsubscribe link enabling recipients to opt out of notifications for a specific post. The link uses hash verification to prevent abuse.

- **Email Send Records**:
  - A new "Email Send Log" tab in the settings records each sent email with time, recipient, subject, status (success/failure), and any error messages to aid troubleshooting.

- **Codebase Refactor**:
  - The plugin is refactored into classes/modules under `includes/` (e.g., `PCN_Mailer`, `PCN_Settings`, `PCN_Unsubscribe`) for improved maintainability and extensibility.

## Installation & Activation

1.  Download the latest release from Releases: https://github.com/Yan-QS/WordPress-Comment-Reply-Notify-Plugin/releases
2.  Upload the extracted `wp-comment-notify` folder to the `/wp-content/plugins/` directory of your WordPress site.
3.  Log in to the WordPress admin panel and go to the "Plugins" page.
4.  Find "WP Comment & Reply Notify" and click "Activate".

## Credentials & Security Recommendations

- It's strongly recommended to supply SMTP credentials via environment variables or your hosting secret manager. You can define constants in `wp-config.php` such as `PCN_SMTP_PASSWORD`, `PCN_SMTP_CLIENT_SECRET`, and `PCN_SMTP_REFRESH_TOKEN`. The admin UI will not echo back sensitive values; when needed you can use the "Clear Credentials" button to remove stored values.

## Configuration Guide

After activation, please find **Settings > WP Comment Notify** in the left menu of the admin panel to enter the plugin configuration page.

### 1. Plugin Master Switch

- **Enable Plugin**: Check this box for the plugin to take over comment notifications. Uncheck to completely disable.

### 2. SMTP Settings

This is the core part of the plugin, please fill it in carefully.

- **Enable SMTP**: Must be checked to use the SMTP settings below.
- **Host**: Your SMTP server address (e.g., `smtp.gmail.com`).
- **Port**: SMTP server port. Common combinations:
  - `465` (with SSL encryption)
  - `587` (with TLS encryption)
- **Encryption**: Select `SSL` or `TLS` according to your provider's requirements.
- **SMTP Auth Required**: Usually needs to be checked.
- **Username**: The full email address used to log in to the SMTP server (e.g., `your-name@gmail.com`).
- **Password**: **Very Important**, for services like Gmail, Outlook, etc., this should be an **App Password**, not your email login password. Please generate an App Password in your email account settings.
- **From Email**: The sender email address displayed in the email. Can be different from "Username", but ensure your provider allows sending on behalf of others.
- **From Name**: The sender name displayed in the email. Leave blank to use the site name by default.
- **Auth Type**: Keep "Normal Login".
- **Login Mechanism**: Recommended to keep "Auto Negotiate". If you encounter authentication issues, try switching to `LOGIN` or `PLAIN`.
- **Force Username as From Address**: Checking this will force the use of "Username" as the sender address and envelope sender, which can improve email delivery rates. Recommended.
- **Force IPv4 Connection**: Check this if your server has issues connecting to SMTP in an IPv6 environment (e.g., `502 Invalid input` error).

### 3. Email Templates

You can edit the email HTML templates for three different scenarios directly in the text box. Placeholders (e.g., `{{author}}`, `{{content}}`) can be used in the templates, but please note that these placeholders are hardcoded in the `includes/WordPress_Mail.php` file. To modify them, you need to edit the PHP file.

New: template styles & preview

- Each template now supports multiple style variants (Modern / Plain / Compact). In the admin "Email Templates" tab you can choose a style separately for `reply`, `new_comment`, and `pending` templates.
- After selecting a style you may click "Load selected style" to load that style's template into the editor as a starting point, or edit a custom template directly and save.
- Click "Preview" in the editor to open an email preview modal that renders the template with sample data so you can inspect the final output. For safety, the preview strips and ignores any PHP code in the template to avoid executing server-side code in the admin UI.
- Style template files are located under `includes/templates/styles/{modern,plain,compact}/`. When you save a custom template the plugin will attempt to write it to `includes/templates/`; if that fails it will fall back to storing the template in the `pcn_templates` option in the database.

Warning: when sending real emails the plugin's renderer (`includes/class-pcn-mailer.php`) will include template files and execute PHP inside them (if present). Only place PHP in templates if you fully trust the environment and understand the security implications.

## Troubleshooting

If email sending fails, please follow these steps:

1.  **Check Configuration**: Carefully check if your SMTP host, port, encryption, username, and password/app password are completely correct.
2.  **Send Test Email**: Enter a recipient email in the "SMTP Test" area and click "Send Test Email".
3.  **View Debug Logs**:
    - After sending the test email, enter a number (e.g., 50) in the "Recent Debug Logs" area below and click "Refresh".
    - Check the log content.
    - **`235 Authentication successful`**: Indicates successful login, the issue might be elsewhere.
    - **`535 Login fail`**: Indicates login failure. This is almost always due to **incorrect password/app password**, **SMTP service not enabled**, or **account security restrictions**. Please regenerate the app password and check your email account status.
    - **`[diag] ...` line**: This log records the connection parameters currently used by the plugin for your verification.

### Convenient Troubleshooting

Create a `smtp_test.php` file in the plugin directory and paste the following content.

```php
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
```

Next, access it via your browser to test the SMTP connection independently: https://your-domain/wp-content/plugins/wp-comment-notify/smtp_test.php

If it still fails (showing `535 Login fail`): This 100% confirms that the issue is with your email account or app password, not the plugin code. Please be sure to regenerate the app password and check your account security status.

> After testing, be sure to delete the `smtp_test.php` file from the server to prevent security risks.

## Security Notes

- **Delete `smtp_test.php`**: If you used our standalone test script `smtp_test.php`, please be sure to delete it from the server after testing is complete to avoid potential security risks.
- **App Password Security**: Do not disclose your email app password in public.
