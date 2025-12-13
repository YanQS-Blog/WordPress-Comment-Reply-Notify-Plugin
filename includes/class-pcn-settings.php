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
        // AJAX load debug logs
        add_action('wp_ajax_pcn_load_debug_logs', array(__CLASS__, 'ajax_load_debug_logs'));
        // AJAX clear debug logs
        add_action('wp_ajax_pcn_clear_debug_logs', array(__CLASS__, 'ajax_clear_debug_logs'));
        // AJAX get stats for dashboard
        add_action('wp_ajax_pcn_get_stats', array(__CLASS__, 'ajax_get_stats'));
        // Generic AJAX form submit for settings page
        add_action('wp_ajax_pcn_ajax_form', array(__CLASS__, 'ajax_handle_form'));
        // AJAX: get style template content for preview/load
        add_action('wp_ajax_pcn_get_style_template', array(__CLASS__, 'ajax_get_style_template'));
        // AJAX: preview rendered template (admin only)
        add_action('wp_ajax_pcn_preview_template', array(__CLASS__, 'ajax_preview_template'));
        // Handle CSV export via admin-post to allow direct download in iframe
        add_action('admin_post_pcn_export_logs', array(__CLASS__, 'export_logs_csv_handler'));
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
        // log limits
        register_setting('pcn_settings_group', 'pcn_log_table_max');
        register_setting('pcn_settings_group', 'pcn_logs_option_limit');
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

            // Do not strip PHP tags here: show templates exactly as stored (allow PHP in templates)

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

        // Enforce configured log limits (prune DB table or option storage to configured caps)
        if (is_admin() && current_user_can('manage_options')) {
            self::enforce_log_limits();
        }

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
        $pcn_preview_nonce = wp_create_nonce('pcn_preview_template');

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
            
            // Use mailer's content-type helper to avoid duplicate functions
            add_filter('wp_mail_content_type', array('PCN_Mailer', 'set_html_content_type'));
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

            remove_filter('wp_mail_content_type', array('PCN_Mailer', 'set_html_content_type'));
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
            // Record this test email attempt into the email logs (DB or option fallback)
            if (class_exists('PCN_Mailer') && method_exists('PCN_Mailer', 'log_email_attempt')) {
                PCN_Mailer::log_email_attempt($test_to, $subject, (bool) $ok, $err);
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
        // Determine filename
        $site = sanitize_file_name(get_bloginfo('name')) ?: 'site';
        if ($days > 0) {
            $filename = sprintf('%s-email-logs-last-%dd-%s.csv', $site, intval($days), date('Ymd-His'));
        } else {
            $filename = sprintf('%s-email-logs-%s.csv', $site, date('Ymd-His'));
        }

        // Check if DB table exists; if not fall back to option-based logs
        $check = $wpdb->get_results($wpdb->prepare("SHOW TABLES LIKE %s", $wpdb->esc_like($table)));
        if (! empty($check)) {
            if ($days > 0) {
                $since = gmdate('Y-m-d H:i:s', time() - intval($days) * 24 * 3600);
                $rows = $wpdb->get_results($wpdb->prepare("SELECT time, `to`, subject, status, error FROM {$table} WHERE time >= %s ORDER BY time DESC", $since), ARRAY_A);
            } else {
                $rows = $wpdb->get_results("SELECT time, `to`, subject, status, error FROM {$table} ORDER BY time DESC", ARRAY_A);
            }
        } else {
            $opt = get_option('pcn_email_logs', array());
            if (! is_array($opt)) { $opt = array(); }
            if ($days > 0 && ! empty($opt)) {
                $since_ts = time() - intval($days) * 24 * 3600;
                $keep = array();
                foreach ($opt as $entry) {
                    $t = isset($entry['time']) ? strtotime($entry['time']) : 0;
                    if ($t >= $since_ts) { $keep[] = $entry; }
                }
                $rows = $keep;
            } else {
                $rows = $opt;
            }
        }

        header('Content-Type: text/csv; charset=UTF-8');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        $out = fopen('php://output', 'w');
        // BOM for Excel
        echo "\xEF\xBB\xBF";
        fputcsv($out, array('time', 'to', 'subject', 'status', 'error'));
        if (! empty($rows) && is_array($rows)) {
            foreach ($rows as $r) {
                $time = isset($r['time']) ? $r['time'] : '';
                $to = isset($r['to']) ? $r['to'] : '';
                $subject = isset($r['subject']) ? $r['subject'] : '';
                $status = isset($r['status']) ? $r['status'] : '';
                $error = isset($r['error']) ? $r['error'] : '';
                fputcsv($out, array($time, $to, $subject, $status, $error));
            }
        }
        fclose($out);
        exit;
    }

    // Public handler for admin-post.php?action=pcn_export_logs
    public static function export_logs_csv_handler() {
        if (! current_user_can('manage_options')) {
            wp_die(__('无权限', 'wp-comment-notify'));
        }
        // Verify nonce
        if (! isset($_REQUEST['pcn_show_logs_nonce']) || ! check_admin_referer('pcn_show_logs', 'pcn_show_logs_nonce')) {
            wp_die(__('无效的请求（nonce 校验失败）', 'wp-comment-notify'));
        }
        $days = isset($_REQUEST['pcn_export_days']) ? intval($_REQUEST['pcn_export_days']) : 0;
        // Call internal exporter
        self::export_logs_csv($days);
        // Ensure script ends after output
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

    // Enforce limits on logs to avoid oversized options or tables.
    public static function enforce_log_limits() {
        global $wpdb;
        // Option-based logs cap
        $opt_limit = intval(get_option('pcn_logs_option_limit', 200));
        if ($opt_limit > 0) {
            $opt = get_option('pcn_email_logs', array());
            if (is_array($opt) && count($opt) > $opt_limit) {
                $trimmed = array_slice($opt, 0, $opt_limit);
                update_option('pcn_email_logs', $trimmed, false);
                self::debug_log_append('[logs-maintenance] trimmed option logs to ' . intval($opt_limit));
            }
        }

        // DB table cap
        $table = $wpdb->prefix . 'pcn_email_logs';
        $check = $wpdb->get_results($wpdb->prepare("SHOW TABLES LIKE %s", $wpdb->esc_like($table)));
        if (! empty($check)) {
            $max_rows = intval(get_option('pcn_log_table_max', 1000));
            if ($max_rows > 0) {
                // remove older rows beyond limit
                $wpdb->query($wpdb->prepare("DELETE FROM {$table} WHERE id NOT IN (SELECT id FROM (SELECT id FROM {$table} ORDER BY id DESC LIMIT %d) x)", $max_rows));
                self::debug_log_append('[logs-maintenance] ensured DB log rows <= ' . intval($max_rows));
            }
        }
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

    public static function ajax_load_debug_logs() {
        if (! current_user_can('manage_options')) {
            wp_send_json_error('permission');
        }
        // optional nonce check when provided
        if (isset($_REQUEST['nonce'])) {
            check_ajax_referer('pcn_test_smtp', 'nonce');
        }
        $logs = get_option('pcn_debug_log', array());
        if (! is_array($logs)) { $logs = array(); }
        wp_send_json_success(array('logs' => $logs));
    }

    public static function ajax_clear_debug_logs() {
        if (! current_user_can('manage_options')) {
            wp_send_json_error('permission');
        }
        check_ajax_referer('pcn_test_smtp', 'nonce');
        delete_option('pcn_debug_log');
        wp_send_json_success(array('msg' => __('已清空 SMTP 调试日志。', 'wp-comment-notify')));
    }

    public static function ajax_get_stats() {
        if (! current_user_can('manage_options')) {
            wp_send_json_error('permission');
        }
        // optional nonce check
        if (isset($_REQUEST['nonce'])) {
            check_ajax_referer('pcn_stats', 'nonce');
        }
        $days = isset($_REQUEST['days']) ? max(1, intval($_REQUEST['days'])) : 7;
        $force = ! empty($_REQUEST['force']);

        // Cache key per-days
        $cache_key = 'pcn_stats_' . intval($days);
        if (! $force) {
            $cached = get_transient($cache_key);
            if ($cached !== false) {
                wp_send_json_success($cached);
            }
        }
        global $wpdb;
        $table = $wpdb->prefix . 'pcn_email_logs';

        $labels = array();
        $success_series = array();
        $failure_series = array();
        // prepare last N days labels using WP local time (respect site timezone)
        $ts_now = current_time('timestamp');
        for ($i = $days - 1; $i >= 0; $i--) {
            $d = date('Y-m-d', $ts_now - $i * 86400);
            $labels[] = $d;
            $success_series[$d] = 0;
            $failure_series[$d] = 0;
        }

        // Check if DB table exists
        $check = $wpdb->get_results($wpdb->prepare("SHOW TABLES LIKE %s", $wpdb->esc_like($table)));
        $totals = array('success' => 0, 'failure' => 0);
        if (! empty($check)) {
            // totals
            $row = $wpdb->get_row("SELECT SUM(CASE WHEN status='success' THEN 1 ELSE 0 END) AS s, SUM(CASE WHEN status='failure' THEN 1 ELSE 0 END) AS f FROM {$table}");
            if ($row) {
                $totals['success'] = intval($row->s);
                $totals['failure'] = intval($row->f);
            }
            // per-day
            // use site-local midnight for the oldest day
            $since = date('Y-m-d 00:00:00', $ts_now - ($days - 1) * 86400);
            $sql = $wpdb->prepare("SELECT DATE(time) AS d, SUM(CASE WHEN status='success' THEN 1 ELSE 0 END) AS s, SUM(CASE WHEN status='failure' THEN 1 ELSE 0 END) AS f FROM {$table} WHERE time >= %s GROUP BY DATE(time)", $since);
            $rows = $wpdb->get_results($sql);
            if ($rows) {
                foreach ($rows as $r) {
                    $d = $r->d;
                    if (isset($success_series[$d])) {
                        $success_series[$d] = intval($r->s);
                        $failure_series[$d] = intval($r->f);
                    }
                }
            }
        } else {
            // fallback to option logs
            $opt = get_option('pcn_email_logs', array());
            if (is_array($opt)) {
                foreach ($opt as $entry) {
                    $time = isset($entry['time']) ? $entry['time'] : '';
                    $d = $time ? date('Y-m-d', strtotime($time)) : '';
                    if ($d && isset($success_series[$d])) {
                        if (isset($entry['status']) && $entry['status'] === 'success') {
                            $success_series[$d]++;
                            $totals['success']++;
                        } else {
                            $failure_series[$d]++;
                            $totals['failure']++;
                        }
                    }
                }
            }
        }

        // Unsubscribe counts
        $unsub_list = get_option('pcn_unsubscribe_list', array());
        $unsub_actions = get_option('pcn_unsubscribe_actions', array());
        $unsub_count = 0;
        if (is_array($unsub_list)) { $unsub_count = count($unsub_list); }
        // fallback: count successful unsubscribe actions
        if ($unsub_count === 0 && is_array($unsub_actions)) {
            foreach ($unsub_actions as $a) { if (! empty($a['success'])) { $unsub_count++; } }
        }

        // prepare series arrays aligned with labels
        $sdata = array(); $fdata = array();
        foreach ($labels as $d) { $sdata[] = $success_series[$d]; $fdata[] = $failure_series[$d]; }

        $result = array('totals' => $totals, 'labels' => $labels, 'success' => $sdata, 'failure' => $fdata, 'unsubscribes' => $unsub_count);
        // cache for short period to reduce DB pressure
        set_transient($cache_key, $result, 5 * MINUTE_IN_SECONDS);
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

        // If this was a SMTP test submit, include debug logs so client can display them
        if (isset($_POST['pcn_test_smtp'])) {
            $dbg = get_option('pcn_debug_log', array());
            if (! is_array($dbg)) { $dbg = array(); }
            $extra['debug_logs'] = $dbg;
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

        // 模板编辑 (保留原始内容，包括 PHP 标签)
        $templates = array();
        $templates['reply'] = isset($_POST['tpl_reply']) ? wp_unslash($_POST['tpl_reply']) : '';
        $templates['new_comment'] = isset($_POST['tpl_new_comment']) ? wp_unslash($_POST['tpl_new_comment']) : '';
        $templates['pending'] = isset($_POST['tpl_pending']) ? wp_unslash($_POST['tpl_pending']) : '';

        $tpl_dir = PCN_PLUGIN_DIR . 'includes/templates/';
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

        // Save selected template styles (per-template)
        $styles = isset($_POST['pcn_template_style']) && is_array($_POST['pcn_template_style']) ? array_map('sanitize_text_field', $_POST['pcn_template_style']) : array();
        if (! empty($styles)) {
            update_option('pcn_template_style', $styles);
        }

        echo '<div class="updated"><p>' . __('设置已保存。', 'wp-comment-notify') . '</p></div>';
    }

    public static function get_templates_from_files() {
        $base_dir = PCN_PLUGIN_DIR . 'includes/templates/';
        $tpls = array();
        $files = array('reply', 'new_comment', 'pending');

        // Load per-template selected styles
        $styles = get_option('pcn_template_style', array());

        foreach ($files as $f) {
            $content = '';
            $style = isset($styles[$f]) ? $styles[$f] : '';
            if ($style) {
                $styled_path = $base_dir . 'styles/' . $style . '/' . $f . '.php';
                if (file_exists($styled_path)) {
                    $content = file_get_contents($styled_path);
                }
            }
            // fallback to root template file
            if ($content === '') {
                $path = $base_dir . $f . '.php';
                if (file_exists($path)) {
                    $content = file_get_contents($path);
                }
            }
            $tpls[$f] = $content;
        }
        return $tpls;
    }

    public static function ajax_get_style_template() {
        if (! current_user_can('manage_options')) {
            wp_send_json_error('permission');
        }
        $name = isset($_REQUEST['name']) ? sanitize_text_field($_REQUEST['name']) : '';
        $style = isset($_REQUEST['style']) ? sanitize_text_field($_REQUEST['style']) : '';
        if (! in_array($name, array('reply','new_comment','pending'), true) || $style === '') {
            wp_send_json_error('invalid');
        }
        $path = PCN_PLUGIN_DIR . 'includes/templates/styles/' . $style . '/' . $name . '.php';
        // Debug: record attempted path and existence
        if (method_exists(__CLASS__, 'debug_log_append')) {
            self::debug_log_append('[ajax_get_style_template] path=' . $path . ' exists=' . (file_exists($path) ? 'yes' : 'no'));
        }
        if (! file_exists($path)) {
            wp_send_json_error('notfound');
        }
        $content = file_get_contents($path);
        // Return raw file content (preserve PHP tags) so editor shows exact template source
        wp_send_json_success(array('content' => $content));
    }

    public static function ajax_preview_template() {
        if (! current_user_can('manage_options')) {
            wp_send_json_error('permission');
        }
        // nonce required
        if (! isset($_REQUEST['nonce']) || ! check_ajax_referer('pcn_preview_template', 'nonce', false)) {
            wp_send_json_error('invalid_nonce');
        }

        $name = isset($_REQUEST['name']) ? sanitize_text_field($_REQUEST['name']) : '';
        if (! in_array($name, array('reply','new_comment','pending'), true)) {
            wp_send_json_error('invalid_name');
        }

        // Prefer provided content (current editor) to allow preview without saving
        // Preserve submitted source (do not strip PHP tags)
        $content = isset($_REQUEST['content']) ? wp_unslash($_REQUEST['content']) : '';

        if ($content === '') {
            // fallback to saved templates (option or files)
            $saved = get_option('pcn_templates', array());
            if (! empty($saved) && isset($saved[$name])) {
                $content = $saved[$name];
            } else {
                $base = PCN_PLUGIN_DIR . 'includes/templates/';
                // try style-selected file
                $styles = get_option('pcn_template_style', array());
                $style = isset($styles[$name]) ? $styles[$name] : '';
                if ($style) {
                    $p = $base . 'styles/' . $style . '/' . $name . '.php';
                    if (file_exists($p)) { $content = file_get_contents($p); }
                }
                if ($content === '') {
                    $p2 = $base . $name . '.php';
                    if (file_exists($p2)) { $content = file_get_contents($p2); }
                }
            }
        }

        if ($content === '') {
            wp_send_json_error('empty_template');
        }

        // Replace common placeholders with sample data for preview
        $placeholders = array(
            '{{blogname}}' => esc_html(get_bloginfo('name')),
            '{{parent_author}}' => '示例用户',
            '{{parent_content}}' => '<p>这是一条示例评论内容。</p>',
            '{{reply_author}}' => '回复者',
            '{{reply_content}}' => '<p>这是示例回复内容，包含 <strong>富文本</strong>。</p>',
            '{{comment_link}}' => esc_url(home_url('/?p=1#comment-1')),
            '{{unsubscribe_url}}' => esc_url(home_url('/?unsubscribe=1')),
            '{{author}}' => '评论作者',
            '{{content}}' => '<p>示例评论文本</p>',
            '{{post_title}}' => '示例文章标题',
            '{{comment_id}}' => '123',
            '{{comments_waiting}}' => '5',
            '{{approve_url}}' => esc_url(admin_url('comment.php?action=approve&c=123')),
            '{{trash_url}}' => esc_url(admin_url('comment.php?action=trash&c=123')),
            '{{spam_url}}' => esc_url(admin_url('comment.php?action=spam&c=123')),
        );

        // Perform a simple replacement (templates are expected to be HTML with placeholders)
        $rendered = strtr($content, $placeholders);

        // If returned content contains PHP tags, strip them to avoid executing server-side code in preview
        $rendered = preg_replace('#<\?(?:php)?[\s\S]*?\?>#i', '', $rendered);

        wp_send_json_success(array('html' => $rendered));
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
        // If openssl not available, fallback to base64-decoded plaintext
        if (! function_exists('openssl_decrypt')) {
            $decoded = @base64_decode($data, true);
            return $decoded === false ? '' : $decoded;
        }

        // Attempt to decode base64 wrapper first
        $raw = @base64_decode($data, true);
        if ($raw === false) {
            // not base64 - give up
            return '';
        }

        // Try multiple possible keys/ciphers for compatibility across plugin updates
        $salt_variants = array('pcn_secret_key', 'pcn_secret', '');
        $cipher_variants = array('AES-256-CBC', 'AES-128-CBC');

        foreach ($cipher_variants as $cipher) {
            $ivlen = openssl_cipher_iv_length($cipher);
            if ($ivlen <= 0) { continue; }
            if (strlen($raw) <= $ivlen) { continue; }
            $iv = substr($raw, 0, $ivlen);
            $cipher_text = substr($raw, $ivlen);
            foreach ($salt_variants as $salt_name) {
                $key = hash('sha256', wp_salt($salt_name));
                $plain = @openssl_decrypt($cipher_text, $cipher, $key, OPENSSL_RAW_DATA, $iv);
                if ($plain !== false && $plain !== null && $plain !== '') {
                    return $plain;
                }
            }
        }

        // Last resort: maybe stored value was simple base64 of plaintext (legacy fallback)
        $decoded_plain = @base64_decode($data, true);
        if ($decoded_plain !== false && is_string($decoded_plain) && strlen(trim($decoded_plain)) > 0) {
            return $decoded_plain;
        }

        return '';
    }

    // Content-type helper removed; use PCN_Mailer::set_html_content_type() instead

    public static function admin_debug_hook($phpmailer) {
        $phpmailer->SMTPDebug = 2;
        $phpmailer->Debugoutput = function($str, $level) {
            $line = '[' . gmdate('Y-m-d H:i:s') . ' UTC] level=' . $level . ' ' . $str;
            error_log('pcn SMTP debug: ' . $line);
            self::debug_log_append($line);
        };
    }
}
