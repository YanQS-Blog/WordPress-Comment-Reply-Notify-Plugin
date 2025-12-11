<?php
if (! defined('ABSPATH')) {
    exit;
}

class PCN_Settings {

    public static function init() {
        add_action('admin_menu', array(__CLASS__, 'add_admin_menu'));
        add_action('admin_init', array(__CLASS__, 'register_settings'));
    }

    public static function add_admin_menu() {
        add_options_page(
            __('WP Comment Notify', 'wp-comment-notify'),
            __('WP Comment Notify', 'wp-comment-notify'),
            'manage_options',
            'wp-comment-notify',
            array(__CLASS__, 'render_options_page')
        );
    }

    public static function register_settings() {
        register_setting('pcn_settings_group', 'pcn_smtp_settings');
        register_setting('pcn_settings_group', 'pcn_templates');
        register_setting('pcn_settings_group', 'pcn_enabled');
    }

    public static function render_options_page() {
        if (! current_user_can('manage_options')) {
            return;
        }

        self::handle_actions();

        // Prepare data for view
        $smtp = get_option('pcn_smtp_settings', array());
        $enabled = get_option('pcn_enabled', 1);
        // No license enforcement — plugin available by default

        $saved_templates = get_option('pcn_templates');
        $file_templates = self::get_templates_from_files();
        if ($saved_templates && ! empty($saved_templates)) {
            $tpls = wp_parse_args($saved_templates, $file_templates);
        } else {
            $tpls = $file_templates;
        }

        // Prepare logs
        $n = isset($_POST['pcn_logs_n']) ? intval($_POST['pcn_logs_n']) : 50;
        $n = max(1, min(500, $n));
        $logs = get_option('pcn_email_logs', array());
        if (! empty($logs)) {
            $logs_to_show = array_slice($logs, 0, $n);
        } else {
            $logs_to_show = array();
        }

        $debug_logs = get_option('pcn_debug_log', array());

        // Enqueue editor scripts so we can initialize TinyMCE on-demand in the view
        if (is_admin()) {
            wp_enqueue_editor();
        }

        // Include view
        include PCN_PLUGIN_DIR . 'includes/views/settings-page.php';
    }

    private static function handle_actions() {
        if (! current_user_can('manage_options')) {
            return;
        }
        if (isset($_POST['pcn_test_smtp']) && check_admin_referer('pcn_test_smtp')) {
            self::handle_smtp_test();
        }

        if (isset($_POST['pcn_save_settings']) && check_admin_referer('pcn_save_settings')) {
            self::save_settings();
        }
        
        // Clear stored sensitive credentials
        if (isset($_POST['pcn_clear_credentials']) && check_admin_referer('pcn_clear_credentials')) {
            $settings = get_option('pcn_smtp_settings', array());
            $settings['password'] = '';
            $settings['client_secret'] = '';
            $settings['refresh_token'] = '';
            update_option('pcn_smtp_settings', $settings);
            echo '<div class="updated"><p>' . __('已清除敏感凭据（后台已不再回显）。建议使用环境变量提供凭据。', 'wp-comment-notify') . '</p></div>';
        }
        
        if (isset($_POST['pcn_clear_logs']) && check_admin_referer('pcn_show_logs')) {
            delete_option('pcn_email_logs');
            echo '<div class="updated"><p>' . __('已清空邮件发送日志。', 'wp-comment-notify') . '</p></div>';
        }

        if (isset($_POST['pcn_clear_debug_logs']) && check_admin_referer('pcn_test_smtp')) {
            delete_option('pcn_debug_log');
            echo '<div class="updated"><p>' . __('已清空 SMTP 调试日志。', 'wp-comment-notify') . '</p></div>';
        }
    }

    private static function handle_smtp_test() {
        $test_to = sanitize_email($_POST['test_to'] ?? '');
        if (! empty($test_to)) {
            $subject = __('WP Comment Notify SMTP 测试', 'wp-comment-notify');
            $message = '<p>' . __('这是一封测试邮件，用于验证当前 SMTP/TLS/OAuth 配置是否可用。', 'wp-comment-notify') . '</p>';
            
            add_filter('wp_mail_content_type', array(__CLASS__, 'admin_html_content_type'));
            add_action('phpmailer_init', array(__CLASS__, 'admin_debug_hook'), PHP_INT_MAX);

            $ok = wp_mail($test_to, $subject, $message);

            global $phpmailer;
            $err = '';
            if (is_object($phpmailer) && property_exists($phpmailer, 'ErrorInfo')) {
                $err = trim($phpmailer->ErrorInfo);
                if (! empty($err)) {
                    error_log('pcn: SMTP 测试错误信息: ' . $err);
                }
            }

            remove_filter('wp_mail_content_type', array(__CLASS__, 'admin_html_content_type'));
            remove_action('phpmailer_init', array(__CLASS__, 'admin_debug_hook'));

            if ($ok) {
                echo '<div class="updated"><p>' . sprintf(__('测试邮件已发送，请检查收件箱：%s', 'wp-comment-notify'), esc_html($test_to)) . '</p></div>';
                if (! empty($err)) {
                    echo '<div class="notice"><p>' . sprintf(__('PHPMailer 提示信息：%s', 'wp-comment-notify'), esc_html($err)) . '</p></div>';
                } else {
                    echo '<div class="notice"><p>' . __('PHPMailer 未返回错误信息。如未收到邮件，请查看服务器日志中以 “pcn SMTP debug” 开头的记录。', 'wp-comment-notify') . '</p></div>';
                }
                $snap = get_option('pcn_smtp_settings', array());
                $safeSnap = array(
                    'enable_smtp' => ! empty($snap['enable_smtp']),
                    'host' => $snap['host'] ?? '',
                    'port' => isset($snap['port']) ? intval($snap['port']) : '',
                    'encryption' => $snap['encryption'] ?? '',
                    'smtp_auth' => ! empty($snap['smtp_auth']),
                    'auth_type' => $snap['auth_type'] ?? '',
                );
                self::debug_log_append('[settings-snapshot] ' . wp_json_encode($safeSnap));
            } else {
                $msg = __('测试邮件发送失败。', 'wp-comment-notify');
                if (! empty($err)) {
                    $msg .= ' ' . sprintf(__('错误信息：%s', 'wp-comment-notify'), esc_html($err));
                } else {
                    $msg .= ' ' . __('请检查 SMTP 设置与服务器日志（搜索 “pcn SMTP debug”）。', 'wp-comment-notify');
                }
                echo '<div class="error"><p>' . $msg . '</p></div>';
                if (! empty($err)) {
                    self::debug_log_append('[ErrorInfo] ' . $err);
                }
                $snap = get_option('pcn_smtp_settings', array());
                $safeSnap = array(
                    'enable_smtp' => ! empty($snap['enable_smtp']),
                    'host' => $snap['host'] ?? '',
                    'port' => isset($snap['port']) ? intval($snap['port']) : '',
                    'encryption' => $snap['encryption'] ?? '',
                    'smtp_auth' => ! empty($snap['smtp_auth']),
                    'auth_type' => $snap['auth_type'] ?? '',
                );
                self::debug_log_append('[settings-snapshot] ' . wp_json_encode($safeSnap));
            }
        } else {
            echo '<div class="error"><p>' . __('请填写有效的测试收件人邮箱。', 'wp-comment-notify') . '</p></div>';
        }
    }

    private static function save_settings() {
        // 不再处理授权密钥；直接保存其他设置

        // 总开关
        $enabled = ! empty($_POST['pcn_enabled']) ? 1 : 0;
        update_option('pcn_enabled', $enabled);
        $smtp = array();
        $smtp['enable_smtp'] = ! empty($_POST['enable_smtp']) ? 1 : 0;
        $smtp['host'] = sanitize_text_field($_POST['host']);
        $smtp['port'] = intval($_POST['port']);
        $smtp['encryption'] = sanitize_text_field($_POST['encryption']);
        $smtp['smtp_auth'] = ! empty($_POST['smtp_auth']) ? 1 : 0;
        $smtp['username'] = sanitize_text_field($_POST['username']);
        // Handle password: if user provided a non-empty value, encrypt and store it.
        $existing = get_option('pcn_smtp_settings', array());
        $posted_pass = isset($_POST['password']) ? trim($_POST['password']) : '';
        if ($posted_pass !== '') {
            $smtp['password'] = self::encrypt_value($posted_pass);
        } else {
            // keep existing encrypted value if present
            if (! empty($existing['password'])) {
                $smtp['password'] = $existing['password'];
            } else {
                $smtp['password'] = '';
            }
        }
        $smtp['from_email'] = sanitize_email($_POST['from_email'] ?? '');
        $smtp['from_name'] = sanitize_text_field($_POST['from_name'] ?? '');
        $smtp['auth_type'] = sanitize_text_field($_POST['auth_type']);
        $smtp['login_mechanism'] = sanitize_text_field($_POST['login_mechanism'] ?? 'AUTO');
        $smtp['force_from_username'] = ! empty($_POST['force_from_username']) ? 1 : 0;
        $smtp['force_ipv4'] = ! empty($_POST['force_ipv4']) ? 1 : 0;

        $smtp['client_id'] = sanitize_text_field($_POST['client_id']);
        $posted_cs = isset($_POST['client_secret']) ? trim($_POST['client_secret']) : '';
        if ($posted_cs !== '') {
            $smtp['client_secret'] = self::encrypt_value($posted_cs);
        } else {
            if (! empty($existing['client_secret'])) {
                $smtp['client_secret'] = $existing['client_secret'];
            } else {
                $smtp['client_secret'] = '';
            }
        }
        $posted_rt = isset($_POST['refresh_token']) ? trim($_POST['refresh_token']) : '';
        if ($posted_rt !== '') {
            $smtp['refresh_token'] = self::encrypt_value($posted_rt);
        } else {
            if (! empty($existing['refresh_token'])) {
                $smtp['refresh_token'] = $existing['refresh_token'];
            } else {
                $smtp['refresh_token'] = '';
            }
        }
        update_option('pcn_smtp_settings', $smtp);

        // 模板编辑
        $templates = array();
        $templates['reply'] = wp_kses_post($_POST['tpl_reply']);
        $templates['new_comment'] = wp_kses_post($_POST['tpl_new_comment']);
        $templates['pending'] = wp_kses_post($_POST['tpl_pending']);

        $tpl_dir = PCN_PLUGIN_DIR . 'templates/';
        if (! file_exists($tpl_dir)) {
            @mkdir($tpl_dir, 0755, true);
        }
        $saved_to_files = true;
        foreach ($templates as $name => $content) {
            $path = $tpl_dir . $name . '.php';
            $res = @file_put_contents($path, $content);
            if ($res === false) {
                $saved_to_files = false;
                break;
            }
        }
        if (! $saved_to_files) {
            update_option('pcn_templates', $templates);
        } else {
            delete_option('pcn_templates');
        }

        echo '<div class="updated"><p>' . __('设置已保存。', 'wp-comment-notify') . '</p></div>';
    }

    public static function get_templates_from_files() {
        $tpl_dir = PCN_PLUGIN_DIR . 'templates/';
        $tpls = array();
        $files = array('reply', 'new_comment', 'pending');
        foreach ($files as $f) {
            $path = $tpl_dir . $f . '.php';
            if (file_exists($path)) {
                $tpls[$f] = file_get_contents($path);
            } else {
                $tpls[$f] = '';
            }
        }
        return $tpls;
    }

    public static function debug_log_append($line) {
        $max = 500;
        $logs = get_option('pcn_debug_log', array());
        if (! is_array($logs)) {
            $logs = array();
        }
        $logs[] = $line;
        if (count($logs) > $max) {
            $logs = array_slice($logs, -$max);
        }
        update_option('pcn_debug_log', $logs, false);
    }

    // Encrypt a sensitive value using OpenSSL with a key derived from wp_salt().
    // Returns base64-encoded string containing IV and ciphertext, or empty string on failure.
    public static function encrypt_value($plain) {
        if (! is_string($plain) || $plain === '') {
            return '';
        }
        if (! function_exists('openssl_encrypt')) {
            // Fallback: avoid storing plaintext; return base64 of value (not ideal).
            return base64_encode($plain);
        }
        $key = hash('sha256', wp_salt('pcn_secret_key'));
        $ivlen = openssl_cipher_iv_length('AES-256-CBC');
        $iv = openssl_random_pseudo_bytes($ivlen);
        $cipher = openssl_encrypt($plain, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
        if ($cipher === false) {
            return '';
        }
        return base64_encode($iv . $cipher);
    }

    // Decrypt a value previously encrypted with encrypt_value().
    // If input looks like base64 non-encrypted fallback, attempt decode.
    public static function decrypt_value($data) {
        if (! is_string($data) || $data === '') {
            return '';
        }
        if (! function_exists('openssl_decrypt')) {
            // Fallback: assume base64-encoded plaintext
            $decoded = @base64_decode($data, true);
            return $decoded === false ? '' : $decoded;
        }
        $raw = base64_decode($data, true);
        if ($raw === false) {
            return '';
        }
        $key = hash('sha256', wp_salt('pcn_secret_key'));
        $ivlen = openssl_cipher_iv_length('AES-256-CBC');
        if (strlen($raw) <= $ivlen) {
            return '';
        }
        $iv = substr($raw, 0, $ivlen);
        $cipher = substr($raw, $ivlen);
        $plain = openssl_decrypt($cipher, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
        if ($plain === false) {
            return '';
        }
        return $plain;
    }

    public static function admin_html_content_type() {
        return 'text/html';
    }

    public static function admin_debug_hook($phpmailer) {
        $phpmailer->SMTPDebug = 2;
        $phpmailer->Debugoutput = function($str, $level) {
            $line = '[' . gmdate('Y-m-d H:i:s') . ' UTC] level=' . $level . ' ' . $str;
            error_log('pcn SMTP debug: ' . $line);
            self::debug_log_append($line);
        };
    }
}
