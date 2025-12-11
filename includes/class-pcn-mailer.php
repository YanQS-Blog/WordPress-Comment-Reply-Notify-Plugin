<?php
if (! defined('ABSPATH')) {
    exit;
}

class PCN_Mailer {

    private static $last_mail_error = '';

    public static function init() {
        add_action('comment_post', array(__CLASS__, 'handle_comment_post'));
        add_action('phpmailer_init', array(__CLASS__, 'init_phpmailer'), PHP_INT_MAX);
        add_action('wp_mail_failed', array(__CLASS__, 'capture_mail_error'));
        // Queue processing hook
        add_action('pcn_process_queue', array(__CLASS__, 'process_queue'));
    }

    public static function capture_mail_error($error) {
        if (is_wp_error($error)) {
            self::$last_mail_error = $error->get_error_message();
        }
    }

    public static function log_email_attempt($to, $subject, $sent, $error = '') {
        global $wpdb;
        $table = $wpdb->prefix . 'pcn_email_logs';
        // Fallback to option storage if table does not exist
        $check = $wpdb->get_results($wpdb->prepare("SHOW TABLES LIKE %s", $wpdb->esc_like($table)));
        $time = current_time('mysql');
        if (! empty($check)) {
            $wpdb->insert(
                $table,
                array(
                    'time' => $time,
                    'to' => substr($to, 0, 255),
                    'subject' => $subject,
                    'status' => $sent ? 'success' : 'failure',
                    'error' => $error,
                    'meta' => ''
                ),
                array('%s','%s','%s','%s','%s','%s')
            );
            // Keep only recent 1000 rows to cap growth (rotation)
            $wpdb->query("DELETE FROM {$table} WHERE id NOT IN (SELECT id FROM (SELECT id FROM {$table} ORDER BY id DESC LIMIT 1000) x)");
        } else {
            // fallback: keep using option but limit size
            $logs = get_option('pcn_email_logs', array());
            if (! is_array($logs)) { $logs = array(); }
            $log_entry = array('time' => $time, 'to' => $to, 'subject' => $subject, 'status' => $sent ? 'success' : 'failure', 'error' => $error);
            array_unshift($logs, $log_entry);
            if (count($logs) > 100) { $logs = array_slice($logs, 0, 100); }
            update_option('pcn_email_logs', $logs, false);
        }
    }

    public static function set_html_content_type() {
        return 'text/html';
    }

    public static function handle_comment_post($comment_id) {
        // 若未启用插件，则直接跳过
        if (! get_option('pcn_enabled', 1)) {
            return;
        }
        $comment = get_comment($comment_id);
        if (! $comment) {
            return;
        }

        $admin_email = get_bloginfo('admin_email');
        $blogname = wp_specialchars_decode(get_option('blogname'), ENT_QUOTES);
        global $wpdb;
        $comments_waiting = $wpdb->get_var("SELECT count(comment_ID) FROM $wpdb->comments WHERE comment_approved = '0'");

        $parent_id = $comment->comment_parent ? $comment->comment_parent : 0;
        $spam_confirmed = $comment->comment_approved; // 'spam', 0, 1 ...

        // 1) 回复通知：当此评论是对已有评论的回复时，通知父评论作者（若不是管理员自己）
        if ($parent_id && $spam_confirmed !== 'spam') {
            $parent_comment = get_comment($parent_id);
            if ($parent_comment) {
                $parent_author_email = trim($parent_comment->comment_author_email);
                if ($parent_author_email && $parent_author_email !== $admin_email) {
                    // Check if user has unsubscribed
                    if (class_exists('PCN_Unsubscribe') && PCN_Unsubscribe::is_unsubscribed($parent_author_email)) {
                        return;
                    }

                    $to = $parent_author_email;
                    $headers = array();

                    $safe_parent_author = esc_html(trim($parent_comment->comment_author));
                    $safe_parent_content = wp_kses_post($parent_comment->comment_content);
                    $safe_reply_author = esc_html(trim($comment->comment_author));
                    $safe_reply_content = wp_kses_post($comment->comment_content);

                    $unsubscribe_url = class_exists('PCN_Unsubscribe') ? PCN_Unsubscribe::get_unsubscribe_url($parent_author_email) : '#';

                    $subject = sprintf(__('您在 [%s] 的留言有了新回复！', 'wp-comment-notify'), $blogname);
                    $message = self::get_template('reply', array(
                        'blogname' => $blogname,
                        'parent_author' => $safe_parent_author,
                        'parent_content' => nl2br($safe_parent_content),
                        'reply_author' => $safe_reply_author,
                        'reply_content' => nl2br($safe_reply_content),
                        'comment_link' => get_comment_link($parent_id),
                        'unsubscribe_url' => $unsubscribe_url,
                    ));

                    // Enqueue email for asynchronous sending if enabled
                    $queue_enabled = get_option('pcn_queue_enabled', 1);
                    if ($queue_enabled) {
                        self::enqueue_email($to, $subject, $message, $headers, array('comment_id' => $comment_id, 'type' => 'reply'));
                    } else {
                        add_filter('wp_mail_content_type', array(__CLASS__, 'set_html_content_type'));
                        self::$last_mail_error = '';
                        $sent = wp_mail($to, $subject, $message, $headers);
                        self::log_email_attempt($to, $subject, $sent, $sent ? '' : self::$last_mail_error);
                        remove_filter('wp_mail_content_type', array(__CLASS__, 'set_html_content_type'));
                        if (! $sent) {
                            error_log('pcn: 回复通知邮件发送失败，comment_id=' . $comment_id);
                        }
                    }
                }
            }
        }

        // 2) 管理员新评论通知（当 parent_id == 0，即顶级评论且非管理员发起）
        if (! $parent_id && (trim($comment->comment_author_email) !== trim($admin_email)) && $spam_confirmed !== 'spam' && $comment->comment_approved != 0) {
            $to = $admin_email;
            $headers = array();

            $safe_author = esc_html($comment->comment_author);
            $safe_content = wp_kses_post($comment->comment_content);
            $subject = sprintf(__('在「%s」的文章《%s》有新的评论', 'wp-comment-notify'), $blogname, get_the_title($comment->comment_post_ID));

            $approve_url = admin_url("comment.php?action=approve&c={$comment_id}#wpbody-content");
            $trash_url = admin_url("comment.php?action=trash&c={$comment_id}#wpbody-content");
            $spam_url = admin_url("comment.php?action=spam&c={$comment_id}#wpbody-content");

            $message = self::get_template('new_comment', array(
                'author' => $safe_author,
                'content' => nl2br($safe_content),
                'post_title' => get_the_title($comment->comment_post_ID),
                'comment_id' => $comment_id,
                'comments_waiting' => intval($comments_waiting),
                'approve_url' => $approve_url,
                'trash_url' => $trash_url,
                'spam_url' => $spam_url,
            ));
            $queue_enabled = get_option('pcn_queue_enabled', 1);
            if ($queue_enabled) {
                self::enqueue_email($to, $subject, $message, $headers, array('comment_id' => $comment_id, 'type' => 'admin_new'));
            } else {
                add_filter('wp_mail_content_type', array(__CLASS__, 'set_html_content_type'));
                self::$last_mail_error = '';
                $sent = wp_mail($to, $subject, $message, $headers);
                self::log_email_attempt($to, $subject, $sent, $sent ? '' : self::$last_mail_error);
                remove_filter('wp_mail_content_type', array(__CLASS__, 'set_html_content_type'));
                if (! $sent) {
                    error_log('pcn: 管理员新评论通知邮件发送失败，comment_id=' . $comment_id);
                }
            }
        }

        // 3) 需要审核时通知管理员（comment_approved == 0）
        if (! $parent_id && (trim($comment->comment_author_email) !== trim($admin_email)) && $spam_confirmed !== 'spam' && $comment->comment_approved == 0) {
            $to = $admin_email;
            $headers = array();

            $safe_author = esc_html($comment->comment_author);
            $safe_content = wp_kses_post($comment->comment_content);
            $subject = sprintf(__('在「%s」的文章《%s》中有新的评论需要审核', 'wp-comment-notify'), $blogname, get_the_title($comment->comment_post_ID));

            $approve_url = admin_url("comment.php?action=approve&c={$comment_id}#wpbody-content");
            $trash_url = admin_url("comment.php?action=trash&c={$comment_id}#wpbody-content");
            $spam_url = admin_url("comment.php?action=spam&c={$comment_id}#wpbody-content");

            $message = self::get_template('pending', array(
                'author' => $safe_author,
                'content' => nl2br($safe_content),
                'post_title' => get_the_title($comment->comment_post_ID),
                'comment_id' => $comment_id,
                'comments_waiting' => intval($comments_waiting),
                'approve_url' => $approve_url,
                'trash_url' => $trash_url,
                'spam_url' => $spam_url,
            ));

            $queue_enabled = get_option('pcn_queue_enabled', 1);
            if ($queue_enabled) {
                self::enqueue_email($to, $subject, $message, $headers, array('comment_id' => $comment_id, 'type' => 'pending'));
            } else {
                add_filter('wp_mail_content_type', array(__CLASS__, 'set_html_content_type'));
                self::$last_mail_error = '';
                $sent = wp_mail($to, $subject, $message, $headers);
                self::log_email_attempt($to, $subject, $sent, $sent ? '' : self::$last_mail_error);
                remove_filter('wp_mail_content_type', array(__CLASS__, 'set_html_content_type'));
                if (! $sent) {
                    error_log('pcn: 审核通知邮件发送失败，comment_id=' . $comment_id);
                }
            }
        }
    }

    // Queue functions
    public static function enqueue_email($to, $subject, $message, $headers = array(), $meta = array()) {
        $queue = get_option('pcn_email_queue', array());
        if (! is_array($queue)) { $queue = array(); }
        $id = uniqid('pcn_', true);
        $item = array(
            'id' => $id,
            'time' => current_time('mysql'),
            'to' => $to,
            'subject' => $subject,
            'message' => $message,
            'headers' => $headers,
            'attempts' => 0,
            'next_attempt' => time(),
            'meta' => $meta,
        );
        $queue[] = $item;
        update_option('pcn_email_queue', $queue, false);
        // Schedule processor if not scheduled
        if (! wp_next_scheduled('pcn_process_queue')) {
            wp_schedule_single_event(time() + 30, 'pcn_process_queue');
        }
        return $id;
    }

    public static function process_queue() {
        if (! function_exists('get_option')) { return; }
        // Prevent overlapping runs
        if (get_transient('pcn_queue_lock')) { return; }
        set_transient('pcn_queue_lock', 1, 300);

        $queue = get_option('pcn_email_queue', array());
        if (! is_array($queue) || empty($queue)) {
            delete_transient('pcn_queue_lock');
            return;
        }

        $max_per_run = intval(get_option('pcn_queue_batch', 10));
        $max_retries = intval(get_option('pcn_queue_retries', 5));
        $processed = 0;
        $now = time();
        foreach ($queue as $idx => $item) {
            if ($processed >= $max_per_run) { break; }
            if (! isset($item['next_attempt']) || intval($item['next_attempt']) > $now) { continue; }

            // attempt send
            add_filter('wp_mail_content_type', array(__CLASS__, 'set_html_content_type'));
            self::$last_mail_error = '';
            $sent = wp_mail($item['to'], $item['subject'], $item['message'], $item['headers']);
            remove_filter('wp_mail_content_type', array(__CLASS__, 'set_html_content_type'));

            if ($sent) {
                self::log_email_attempt($item['to'], $item['subject'], true, '');
                // remove from queue
                unset($queue[$idx]);
            } else {
                $item['attempts'] = intval($item['attempts']) + 1;
                if ($item['attempts'] > $max_retries) {
                    self::log_email_attempt($item['to'], $item['subject'], false, self::$last_mail_error ?: 'max_retries');
                    unset($queue[$idx]);
                } else {
                    // exponential backoff in seconds
                    $delay = pow(2, $item['attempts']) * 60;
                    $item['next_attempt'] = time() + $delay;
                    $queue[$idx] = $item;
                }
            }
            $processed++;
        }

        // Reindex and save
        if (! empty($queue)) {
            $queue = array_values($queue);
            update_option('pcn_email_queue', $queue, false);
        } else {
            delete_option('pcn_email_queue');
        }

        // If still items remain, schedule next run
        if (! empty($queue) && ! wp_next_scheduled('pcn_process_queue')) {
            wp_schedule_single_event(time() + 60, 'pcn_process_queue');
        }

        delete_transient('pcn_queue_lock');
    }

    public static function get_template($name, $vars = array()) {
        $tpl_dir = PCN_PLUGIN_DIR . 'templates/';
        $path = $tpl_dir . $name . '.php';
        $tpl = '';

        if (file_exists($path)) {
            extract($vars, EXTR_SKIP);
            ob_start();
            include $path;
            $tpl = ob_get_clean();
        } else {
            // 回退到数据库保存的模板（如果存在）
            $saved = get_option('pcn_templates', array());
            if (! empty($saved[$name])) {
                $tpl = $saved[$name];
            }
        }

        if (! empty($tpl)) {
            // 统一执行变量替换（支持 {{var}} 语法），无论来源是文件还是数据库
            foreach ($vars as $k => $v) {
                // 仅替换字符串或数字类型的变量，避免数组/对象导致错误
                if (is_string($v) || is_numeric($v)) {
                    $tpl = str_replace('{{' . $k . '}}', $v, $tpl);
                }
            }
            return $tpl;
        }

        return '';
    }

    public static function init_phpmailer($phpmailer) {
        $settings = get_option('pcn_smtp_settings', array());
        if (empty($settings['enable_smtp'])) {
            return;
        }

        // 开启 SMTP
        $phpmailer->isSMTP();
        if (! empty($settings['host'])) {
            $phpmailer->Host = $settings['host'];
        }
        // 主机名（EHLO/HELO）可提升兼容性
        if (function_exists('get_bloginfo')) {
            $siteHost = parse_url(home_url(), PHP_URL_HOST);
            if (! empty($siteHost)) {
                $phpmailer->Hostname = $siteHost;
            }
        }
        if (! empty($settings['port'])) {
            $phpmailer->Port = intval($settings['port']);
        }
        // 当使用 465/SSL 时，关闭 AutoTLS，避免 STARTTLS 干扰
        $phpmailer->SMTPAutoTLS = true;
        if (! empty($settings['encryption'])) {
            $phpmailer->SMTPSecure = $settings['encryption'];
        }
        if ((! empty($settings['port']) && intval($settings['port']) === 465) || (! empty($settings['encryption']) && $settings['encryption'] === 'ssl')) {
            $phpmailer->SMTPAutoTLS = false;
        }
        // 587/TLS 场景下，显式启用 STARTTLS
        if ((! empty($settings['port']) && intval($settings['port']) === 587) || (! empty($settings['encryption']) && $settings['encryption'] === 'tls')) {
            $phpmailer->SMTPSecure = 'tls';
            $phpmailer->SMTPAutoTLS = true;
        }

        // 与常见实现对齐：统一字符集与编码（改为 8bit）
        $phpmailer->CharSet = 'UTF-8';
        $phpmailer->Encoding = '8bit';

        // 避免长连接导致异常，默认不保持连接
        $phpmailer->SMTPKeepAlive = false;

        $phpmailer->SMTPAuth = ! empty($settings['smtp_auth']);
        if ($phpmailer->SMTPAuth && (! empty($settings['username']) || ! empty($settings['password']))) {
            $phpmailer->Username = $settings['username'];
            // Prefer environment constant if set; otherwise decrypt stored value
            if (defined('PCN_SMTP_PASSWORD') && PCN_SMTP_PASSWORD !== '') {
                $phpmailer->Password = PCN_SMTP_PASSWORD;
            } else {
                if (! empty($settings['password']) && method_exists('PCN_Settings', 'decrypt_value')) {
                    $phpmailer->Password = PCN_Settings::decrypt_value($settings['password']);
                } else {
                    $phpmailer->Password = '';
                }
            }
            // 若选择普通登录，按登录机制设置；AUTO 则让 PHPMailer 自行协商
            if (empty($settings['auth_type']) || $settings['auth_type'] === 'login') {
                $mechanism = ! empty($settings['login_mechanism']) ? strtoupper($settings['login_mechanism']) : 'AUTO';
                if ($mechanism === 'AUTO') {
                    $phpmailer->AuthType = '';
                } else if (in_array($mechanism, array('LOGIN', 'PLAIN'), true)) {
                    $phpmailer->AuthType = $mechanism;
                } else {
                    $phpmailer->AuthType = '';
                }
            }
            // 记录一次轻量诊断（掩码用户名，仅域名）
            $masked = '';
            if (! empty($settings['username'])) {
                $parts = explode('@', $settings['username']);
                if (count($parts) === 2) {
                    $masked = '***@' . $parts[1];
                }
            }
            $diag = 'pcn: SMTP auth using ' . ($phpmailer->AuthType ?: 'auto') . ', user=' . $masked . ', host=' . ($settings['host'] ?? '') . ', port=' . ($settings['port'] ?? '') . ', enc=' . ($settings['encryption'] ?? '');
            error_log($diag);
            
            // 同步到最近调试日志选项，便于在后台查看
            $line = '[diag] ' . str_replace('pcn: ', '', $diag);
            if (class_exists('PCN_Settings') && method_exists('PCN_Settings', 'debug_log_append')) {
                PCN_Settings::debug_log_append($line);
            } else {
                // Fallback if PCN_Settings is not loaded or method not available
                $logs = get_option('pcn_debug_log', array());
                if (! is_array($logs)) { $logs = array(); }
                $logs[] = $line;
                if (count($logs) > 500) { $logs = array_slice($logs, -500); }
                update_option('pcn_debug_log', $logs, false);
            }
        }

        // 统一设置发信地址/名称；可选强制与用户名一致
        try {
            $useUsername = ! empty($settings['force_from_username']) && ! empty($settings['username']);
            $fromEmail = $useUsername ? $settings['username'] : (! empty($settings['from_email']) ? $settings['from_email'] : $phpmailer->From);
            if (empty($fromEmail) && ! empty($settings['username'])) {
                $fromEmail = $settings['username'];
            }
            $fromName = ! empty($settings['from_name']) ? $settings['from_name'] : wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES);
            if (! empty($fromEmail)) {
                $phpmailer->setFrom($fromEmail, $fromName, false);
            }
            // Envelope Sender（Return-Path）也设置为用户名以提升兼容性
            if (! empty($settings['username'])) {
                $phpmailer->Sender = $settings['username'];
            }
        } catch (\Exception $e) {
            error_log('pcn: 设置发信地址失败: ' . $e->getMessage());
        }

        // 强制使用 IPv4 连接（通过 socket 上下文 bindto 设置）
        if (! empty($settings['force_ipv4'])) {
            if (! isset($phpmailer->SMTPOptions['socket'])) {
                $phpmailer->SMTPOptions['socket'] = array();
            }
            $phpmailer->SMTPOptions['socket']['bindto'] = '0.0.0.0:0';
            error_log('pcn: SMTP forced to IPv4 via socket bindto');
        }

        // 强制证书校验（可通过设置添加 cafile）
        $ssl_opts = array(
            'verify_peer' => true,
            'verify_peer_name' => true,
            'allow_self_signed' => false,
        );
        if (! empty($settings['cafile'])) {
            $ssl_opts['cafile'] = $settings['cafile'];
        }
        $phpmailer->SMTPOptions = array('ssl' => $ssl_opts);

        // 如果选择 OAuth2，且库可用，则尝试设置 XOAUTH2
        if (! empty($settings['auth_type']) && $settings['auth_type'] === 'oauth2') {
            if (class_exists('\PHPMailer\\PHPMailer\\OAuth') && class_exists('\League\\OAuth2\\Client\\Provider\\Google')) {
                    try {
                    $clientSecret = '';
                    if (defined('PCN_SMTP_CLIENT_SECRET') && PCN_SMTP_CLIENT_SECRET !== '') {
                        $clientSecret = PCN_SMTP_CLIENT_SECRET;
                    } else {
                        if (! empty($settings['client_secret']) && method_exists('PCN_Settings', 'decrypt_value')) {
                            $clientSecret = PCN_Settings::decrypt_value($settings['client_secret']);
                        }
                    }
                    $provider = new \League\OAuth2\Client\Provider\Google([
                        'clientId' => $settings['client_id'],
                        'clientSecret' => $clientSecret,
                    ]);

                    $phpmailer->AuthType = 'XOAUTH2';
                    // Prefer environment constant for refresh token; otherwise decrypt stored value
                    $refreshToken = '';
                    if (defined('PCN_SMTP_REFRESH_TOKEN') && PCN_SMTP_REFRESH_TOKEN !== '') {
                        $refreshToken = PCN_SMTP_REFRESH_TOKEN;
                    } else {
                        if (! empty($settings['refresh_token']) && method_exists('PCN_Settings', 'decrypt_value')) {
                            $refreshToken = PCN_Settings::decrypt_value($settings['refresh_token']);
                        }
                    }
                    $phpmailer->setOAuth(new \PHPMailer\PHPMailer\OAuth([
                        'provider' => $provider,
                        'clientId' => $settings['client_id'],
                        'clientSecret' => $clientSecret,
                        'refreshToken' => $refreshToken,
                        'userName' => $phpmailer->From,
                    ]));
                } catch (Exception $e) {
                    error_log('pcn: OAuth2 初始化失败: ' . $e->getMessage());
                }
            }
        }
    }
}
