<?php
if (! defined('ABSPATH')) {
    exit;
}

class PCN_Unsubscribe {

    public static function init() {
        add_action('init', array(__CLASS__, 'handle_unsubscribe_request'));
    }

    public static function handle_unsubscribe_request() {
        if (isset($_GET['pcn_action']) && $_GET['pcn_action'] === 'unsubscribe' && isset($_GET['email']) && isset($_GET['ts']) && isset($_GET['sig'])) {
            $email = sanitize_email($_GET['email']);
            $ts = intval($_GET['ts']);
            $sig = sanitize_text_field($_GET['sig']);

            // Verify signature and expiry (短期有效 — 7 天)
            $max_age = 7 * 24 * 3600;
            if (! self::verify_sig($email, $ts, $sig)) {
                wp_die(esc_html__('链接无效或已被篡改。', 'wp-comment-notify'), esc_html__('错误', 'wp-comment-notify'), array('response' => 403));
                return;
            }
            if (time() - $ts > $max_age) {
                wp_die(esc_html__('链接已过期。请在后台重新生成并发送邮件。', 'wp-comment-notify'), esc_html__('链接过期', 'wp-comment-notify'), array('response' => 403));
                return;
            }

            // Check existing state
            if (self::is_unsubscribed($email)) {
                wp_die(esc_html__('该邮箱已取消订阅，无需重复操作。', 'wp-comment-notify'), esc_html__('已取消订阅', 'wp-comment-notify'), array('response' => 200));
                return;
            }

            // Record the unsubscribe with timestamp
            self::add_to_blocklist($email, $ts);
            wp_die(esc_html__('您已成功取消订阅本站的评论回复通知。', 'wp-comment-notify'), esc_html__('取消订阅成功', 'wp-comment-notify'), array('response' => 200));
        }
    }

    public static function get_unsubscribe_url($email) {
        $email = sanitize_email($email);
        $ts = time();
        $sig = self::generate_sig($email, $ts);
        return add_query_arg(array(
            'pcn_action' => 'unsubscribe',
            'email' => urlencode($email),
            'ts' => $ts,
            'sig' => $sig,
        ), home_url('/'));
    }

    public static function is_unsubscribed($email) {
        $blocklist = get_option('pcn_unsubscribe_list', array());
        if (! is_array($blocklist)) {
            return false;
        }
        return isset($blocklist[$email]);
    }

    private static function add_to_blocklist($email, $ts = null) {
        $blocklist = get_option('pcn_unsubscribe_list', array());
        if (! is_array($blocklist)) {
            $blocklist = array();
        }
        $blocklist[$email] = $ts ? intval($ts) : time();
        update_option('pcn_unsubscribe_list', $blocklist, false);
    }

    private static function generate_sig($email, $ts) {
        $key = wp_salt('pcn_unsubscribe');
        return hash_hmac('sha256', $email . '|' . intval($ts), $key);
    }

    private static function verify_sig($email, $ts, $sig) {
        $expected = self::generate_sig($email, $ts);
        return hash_equals($expected, $sig);
    }
}
