<?php
if (! defined('ABSPATH')) {
    exit;
}

class PCN_Settings {

    public static function init() {
        add_action('admin_menu', array(__CLASS__, 'add_admin_menu'));
        add_action('admin_init', array(__CLASS__, 'register_settings'));
        // AJAX diagnostics
        add_action('wp_ajax_pcn_run_diagnostics', array(__CLASS__, 'ajax_run_diagnostics'));
        // AJAX refresh logs
        add_action('wp_ajax_pcn_refresh_logs', array(__CLASS__, 'ajax_refresh_logs'));
        // Generic AJAX form submit for settings page
        add_action('wp_ajax_pcn_ajax_form', array(__CLASS__, 'ajax_handle_form'));
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
        // Only call if the function exists (older WP versions may not have it).
        if (is_admin() && function_exists('wp_enqueue_editor')) {
            wp_enqueue_editor();
        }

        // Prepare queue info for view
        $queue = get_option('pcn_email_queue', array());
        $queue_count = is_array($queue) ? count($queue) : 0;
        $smtp_options = array(
            'queue_enabled' => get_option('pcn_queue_enabled', 1),
            'queue_batch' => get_option('pcn_queue_batch', 10),
            'queue_retries' => get_option('pcn_queue_retries', 5),
        );
        $queue_nonce = wp_create_nonce('pcn_queue_action');

        // Include view
        include PCN_PLUGIN_DIR . 'includes/views/settings-page.php';
    }

    private static function handle_actions() {
        if (! current_user_can('manage_options')) {
            return;
        }
        if (isset($_POST['pcn_test_smtp']) && check_admin_referer('pcn_test_smtp', 'pcn_test_smtp_nonce')) {
            self::handle_smtp_test();
        }

        if (isset($_POST['pcn_save_settings']) && check_admin_referer('pcn_save_settings')) {
            self::save_settings();
        }
        
        // Clear stored sensitive credentials
        if (isset($_POST['pcn_clear_credentials']) && check_admin_referer('pcn_clear_credentials', 'pcn_clear_credentials_nonce')) {
            $settings = get_option('pcn_smtp_settings', array());
            $settings['password'] = '';
            $settings['client_secret'] = '';
            $settings['refresh_token'] = '';
            update_option('pcn_smtp_settings', $settings);
            echo '<div class="updated"><p>' . __('已清除敏感凭据（后台已不再回显）。建议使用环境变量提供凭据。', 'wp-comment-notify') . '</p></div>';
        }
        
        if (isset($_POST['pcn_clear_logs']) && check_admin_referer('pcn_show_logs', 'pcn_show_logs_nonce')) {
            delete_option('pcn_email_logs');
            echo '<div class="updated"><p>' . __('已清空邮件发送日志。', 'wp-comment-notify') . '</p></div>';
        }

        if (isset($_POST['pcn_clear_debug_logs']) && check_admin_referer('pcn_test_smtp', 'pcn_test_smtp_nonce')) {
            delete_option('pcn_debug_log');
            echo '<div class="updated"><p>' . __('已清空 SMTP 调试日志。', 'wp-comment-notify') . '</p></div>';
        }

        // Migrate legacy option-based logs to DB table if needed
        if (is_admin() && current_user_can('manage_options')) {
            self::migrate_option_logs_to_db();
        }

        // Export logs CSV (POST submit)
        if (isset($_POST['pcn_export_logs']) && check_admin_referer('pcn_show_logs', 'pcn_show_logs_nonce')) {
            $days = isset($_POST['pcn_export_days']) ? intval($_POST['pcn_export_days']) : 0;
            self::export_logs_csv($days);
        }

        // Apply retention policy
        if (isset($_POST['pcn_set_retention']) && check_admin_referer('pcn_show_logs', 'pcn_show_logs_nonce')) {
            $days = isset($_POST['pcn_retention_days']) ? intval($_POST['pcn_retention_days']) : 0;
            if ($days > 0) {
                self::apply_retention_policy($days);
                echo '<div class="updated"><p>' . sprintf(__('已应用保留策略：保留最近 %d 天的日志，其余已删除。', 'wp-comment-notify'), $days) . '</p></div>';
            } else {
                echo '<div class="error"><p>' . __('请提供大于 0 的保留天数。', 'wp-comment-notify') . '</p></div>';
            }
        }

        // Manual queue processing / clearing (from settings page)
        if (isset($_POST['pcn_process_queue']) && check_admin_referer('pcn_save_settings')) {
            if (class_exists('PCN_Mailer') && method_exists('PCN_Mailer', 'process_queue')) {
                PCN_Mailer::process_queue();
                echo '<div class="updated"><p>' . __('队列已处理（尽可能处理批次内邮件）。', 'wp-comment-notify') . '</p></div>';
            } else {
                echo '<div class="error"><p>' . __('队列处理器不可用。', 'wp-comment-notify') . '</p></div>';
            }
        }

        if (isset($_POST['pcn_clear_queue']) && check_admin_referer('pcn_save_settings')) {
            delete_option('pcn_email_queue');
            echo '<div class="updated"><p>' . __('邮件队列已清空。', 'wp-comment-notify') . '</p></div>';
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

    private static function migrate_option_logs_to_db() {
        global $wpdb;
        $table = $wpdb->prefix . 'pcn_email_logs';
        $option_logs = get_option('pcn_email_logs', array());
        if (empty($option_logs) || ! is_array($option_logs)) {
            return;
        }
        // Check if table exists
        $check = $wpdb->get_results($wpdb->prepare("SHOW TABLES LIKE %s", $wpdb->esc_like($table)));
        if (empty($check)) {
            return;
        }
        // Determine if table already has rows; if so, skip migration
        $count = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$table}");
        if ($count > 0) {
            // remove legacy option to avoid repeated migrations
            delete_option('pcn_email_logs');
            return;
        }
        foreach (array_reverse($option_logs) as $entry) {
            $wpdb->insert(
                $table,
                array(
                    'time' => isset($entry['time']) ? $entry['time'] : current_time('mysql'),
                    'to' => isset($entry['to']) ? substr($entry['to'], 0, 255) : '',
                    'subject' => isset($entry['subject']) ? $entry['subject'] : '',
                    'status' => isset($entry['status']) ? $entry['status'] : 'failure',
                    'error' => isset($entry['error']) ? $entry['error'] : '',
                    'meta' => ''
                ),
                array('%s','%s','%s','%s','%s','%s')
            );
        }
        delete_option('pcn_email_logs');
    }

    private static function export_logs_csv($days = 0) {
        global $wpdb;
        $table = $wpdb->prefix . 'pcn_email_logs';
        // Build query
        if ($days > 0) {
            $since = gmdate('Y-m-d H:i:s', time() - intval($days) * 24 * 3600);
            $rows = $wpdb->get_results($wpdb->prepare("SELECT time, `to`, subject, status, error FROM {$table} WHERE time >= %s ORDER BY time DESC", $since), ARRAY_A);
            $filename = 'pcn-email-logs-last-' . intval($days) . 'd-' . date('Ymd-His') . '.csv';
        } else {
            $rows = $wpdb->get_results("SELECT time, `to`, subject, status, error FROM {$table} ORDER BY time DESC", ARRAY_A);
            $filename = 'pcn-email-logs-' . date('Ymd-His') . '.csv';
        }

        if (empty($rows)) {
            return false;
        }

        header('Content-Type: text/csv; charset=UTF-8');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        $out = fopen('php://output', 'w');
        // BOM for Excel
        echo "\xEF\xBB\xBF";
        fputcsv($out, array('time', 'to', 'subject', 'status', 'error'));
        foreach ($rows as $r) {
            fputcsv($out, array($r['time'], $r['to'], $r['subject'], $r['status'], $r['error']));
        }
        fclose($out);
        exit;
    }

    private static function apply_retention_policy($days) {
        global $wpdb;
        $table = $wpdb->prefix . 'pcn_email_logs';
        $days = intval($days);
        if ($days <= 0) { return; }
        $threshold = gmdate('Y-m-d H:i:s', time() - $days * 24 * 3600);

        // Ensure the table exists before running DELETE; otherwise fall back to option-based logs
        $check = $wpdb->get_results($wpdb->prepare("SHOW TABLES LIKE %s", $wpdb->esc_like($table)));
        if (empty($check)) {
            // Fallback: filter legacy option logs if present
            $opt = get_option('pcn_email_logs', array());
            if (is_array($opt) && ! empty($opt)) {
                $keep = array();
                foreach ($opt as $entry) {
                    $t = isset($entry['time']) ? $entry['time'] : '';
                    if ($t === '' || strtotime($t) >= strtotime($threshold)) {
                        $keep[] = $entry;
                    }
                }
                update_option('pcn_email_logs', $keep);
            }
            return;
        }

        $wpdb->query($wpdb->prepare("DELETE FROM {$table} WHERE time < %s", $threshold));
    }

    public static function ajax_run_diagnostics() {
        if (! current_user_can('manage_options')) {
            wp_send_json_error('permission');
        }
        check_ajax_referer('pcn_diagnostics', 'nonce');

        $settings = get_option('pcn_smtp_settings', array());
        $result = array();

        // Host resolution
        $host = $settings['host'] ?? '';
        if (empty($host)) {
            $result['host_resolution'] = array('ok' => false, 'msg' => 'No SMTP host configured');
        } else {
            $ip = gethostbyname($host);
            if ($ip === $host || empty($ip)) {
                $result['host_resolution'] = array('ok' => false, 'msg' => "DNS lookup failed for {$host}");
            } else {
                $result['host_resolution'] = array('ok' => true, 'msg' => "Resolved to {$ip}");
            }
        }

        // MX / SPF checks for from domain
        $from = $settings['from_email'] ?? get_bloginfo('admin_email');
        $domain = '';
        if ($from && is_email($from)) {
            $parts = explode('@', $from);
            if (count($parts) === 2) { $domain = $parts[1]; }
        }
        if ($domain) {
            $mx = array();
            $has_mx = function_exists('getmxrr') && @getmxrr($domain, $mx);
            $result['mx'] = array('ok' => (bool) $has_mx, 'msg' => $has_mx ? 'MX records found' : 'No MX records');
            // SPF check
            $txts = dns_get_record($domain, DNS_TXT);
            $spf_found = false;
            if ($txts && is_array($txts)) {
                foreach ($txts as $t) {
                    if (isset($t['txt']) && stripos($t['txt'], 'v=spf1') !== false) { $spf_found = true; break; }
                }
            }
            $result['spf'] = array('ok' => (bool) $spf_found, 'msg' => $spf_found ? 'SPF record present' : 'No SPF record found');
        } else {
            $result['mx'] = array('ok' => false, 'msg' => 'No from-domain to check');
            $result['spf'] = array('ok' => false, 'msg' => 'No from-domain to check');
        }

        // Try connecting to SMTP host:port
        $port = isset($settings['port']) ? intval($settings['port']) : 25;
        $encryption = $settings['encryption'] ?? '';
        $timeout = 6;
        $conn_result = array('ok' => false, 'msg' => '');
        if (! empty($host)) {
            $transport = 'tcp';
            $remote = $host . ':' . $port;
            $errstr = '';
            $errno = 0;
            $fp = @stream_socket_client("{$transport}://{$remote}", $errno, $errstr, $timeout);
            if (! $fp) {
                $conn_result['ok'] = false;
                $conn_result['msg'] = "Connection failed: {$errstr} (errno {$errno})";
            } else {
                $conn_result['ok'] = true;
                $meta = stream_get_meta_data($fp);
                $conn_result['msg'] = 'Connected (transport tcp)';
                fclose($fp);
            }
            // If SSL wrapper desired, try ssl://
            if ($encryption === 'ssl' && !$conn_result['ok']) {
                $fp2 = @stream_socket_client("ssl://{$remote}", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT);
                if ($fp2) {
                    $conn_result['ok'] = true;
                    $conn_result['msg'] = 'SSL connect succeeded';
                    fclose($fp2);
                }
            }
        } else {
            $conn_result['ok'] = false;
            $conn_result['msg'] = 'No host configured';
        }
        $result['connect'] = $conn_result;

        // Certificate info (best effort for SSL)
        $cert_info = array('ok' => false, 'msg' => 'Not checked');
        if ($encryption === 'ssl' && ! empty($host)) {
            $ctx = stream_context_create(array('ssl' => array('capture_peer_cert' => true, 'verify_peer' => false)));
            $stream = @stream_socket_client("ssl://{$host}:{$port}", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $ctx);
            if ($stream) {
                $cont = stream_context_get_params($stream);
                if (! empty($cont['options']['ssl']['peer_certificate'])) {
                    $cert = $cont['options']['ssl']['peer_certificate'];
                    if (function_exists('openssl_x509_parse')) {
                        $parsed = openssl_x509_parse($cert);
                        $cert_info['ok'] = true;
                        $cert_info['msg'] = 'Cert parsed';
                        $cert_info['parsed'] = $parsed;
                    } else {
                        $cert_info['ok'] = true;
                        $cert_info['msg'] = 'Certificate present (openssl missing)';
                    }
                }
                fclose($stream);
            } else {
                $cert_info['ok'] = false;
                $cert_info['msg'] = "Certificate check failed: {$errstr}";
            }
        }
        $result['certificate'] = $cert_info;

        wp_send_json_success($result);
    }

    public static function ajax_refresh_logs() {
        if (! current_user_can('manage_options')) {
            wp_send_json_error('permission');
        }
        check_ajax_referer('pcn_show_logs', 'nonce');

        global $wpdb;
        $table = $wpdb->prefix . 'pcn_email_logs';
        $n = isset($_POST['n']) ? intval($_POST['n']) : 50;
        $n = max(1, min(500, $n));

        // If DB table exists, read from it; otherwise fallback to option
        $check = $wpdb->get_results($wpdb->prepare("SHOW TABLES LIKE %s", $wpdb->esc_like($table)));
        $rows = array();
        if (! empty($check)) {
            $rows = $wpdb->get_results($wpdb->prepare("SELECT time, `to`, subject, status, error FROM {$table} ORDER BY time DESC LIMIT %d", $n), ARRAY_A);
        } else {
            $opt = get_option('pcn_email_logs', array());
            if (is_array($opt)) {
                $sliced = array_slice($opt, 0, $n);
                foreach ($sliced as $r) {
                    $rows[] = array(
                        'time' => $r['time'] ?? '',
                        'to' => $r['to'] ?? '',
                        'subject' => $r['subject'] ?? '',
                        'status' => $r['status'] ?? '',
                        'error' => $r['error'] ?? '',
                    );
                }
            }
        }

        wp_send_json_success(array('rows' => $rows));
    }

    public static function ajax_handle_form() {
        if (! current_user_can('manage_options')) {
            wp_send_json_error('permission');
        }

        // Capture any output produced by handle_actions
        ob_start();
        self::handle_actions();
        $html = ob_get_clean();

        // Optionally return also refreshed snippets (logs table) by invoking ajax_refresh_logs if requested
        $extra = array();
        if (isset($_POST['pcn_refresh_logs']) || isset($_POST['pcn_show_logs']) || isset($_POST['pcn_export_logs'])) {
            // provide current logs snapshot
            ob_start();
            // reuse ajax_refresh_logs to get rows
            $rows_resp = array('rows' => array());
            global $wpdb;
            $table = $wpdb->prefix . 'pcn_email_logs';
            $n = isset($_POST['pcn_logs_n']) ? intval($_POST['pcn_logs_n']) : 50;
            $n = max(1, min(500, $n));
            $check = $wpdb->get_results($wpdb->prepare("SHOW TABLES LIKE %s", $wpdb->esc_like($table)));
            if (! empty($check)) {
                $rows = $wpdb->get_results($wpdb->prepare("SELECT time, `to`, subject, status, error FROM {$table} ORDER BY time DESC LIMIT %d", $n), ARRAY_A);
                $rows_resp['rows'] = $rows;
            } else {
                $opt = get_option('pcn_email_logs', array());
                if (is_array($opt)) {
                    $rows_resp['rows'] = array_slice($opt, 0, $n);
                }
            }
            $extra['logs'] = $rows_resp['rows'];
            ob_end_clean();
        }

        wp_send_json_success(array('html' => $html, 'extra' => $extra));
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

        // Queue settings
        $queue_enabled = ! empty($_POST['pcn_queue_enabled']) ? 1 : 0;
        update_option('pcn_queue_enabled', $queue_enabled);
        $batch = isset($_POST['pcn_queue_batch']) ? max(1, intval($_POST['pcn_queue_batch'])) : 10;
        update_option('pcn_queue_batch', $batch);
        $retries = isset($_POST['pcn_queue_retries']) ? max(0, intval($_POST['pcn_queue_retries'])) : 5;
        update_option('pcn_queue_retries', $retries);

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
