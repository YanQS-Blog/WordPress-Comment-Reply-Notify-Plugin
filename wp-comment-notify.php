<?php
/**
 * Plugin Name: WP Comment & Reply Notify
 * Plugin URI:  https://yanqs.me/wp-comment-notify-plugin/
 * Description: 在评论发布时发送上级用户回复通知邮件&管理员通知邮件（包含安全与 HTML 发送的改良实现）。
 * Version:     2.2.0
 * Author:      YanQS
 * Author URI:  https://yanqs.me/
 * License:     GPL2
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: wp-comment-notify
 * Domain Path: /languages
 */

// 安全检查，防止直接访问
if (! defined('ABSPATH')) {
    exit;
}

// 插件目录常量
if (! defined('PCN_PLUGIN_DIR')) {
    define('PCN_PLUGIN_DIR', plugin_dir_path(__FILE__));
}

// 包含实现文件（已包含改良版实现）
require_once PCN_PLUGIN_DIR . 'includes/class-pcn-unsubscribe.php';
PCN_Unsubscribe::init();

require_once PCN_PLUGIN_DIR . 'includes/class-pcn-mailer.php';
PCN_Mailer::init();

// 后台管理页面（仅在 admin 请求时加载）
if (is_admin()) {
    require_once PCN_PLUGIN_DIR . 'includes/class-pcn-settings.php';
    PCN_Settings::init();
}

// 激活/卸载钩子
function pcn_activate() {
}
register_activation_hook(__FILE__, 'pcn_activate');

function pcn_deactivate() {
    // 卸载时不删除设置，以便用户重新激活
}
register_deactivation_hook(__FILE__, 'pcn_deactivate');

// 插件就绪
add_action('plugins_loaded', function() {
    load_plugin_textdomain('wp-comment-notify', false, dirname(plugin_basename(__FILE__)) . '/languages');
    // 已由 includes 中的 add_action 注册主逻辑
});

?>
