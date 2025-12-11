<?php
if (! defined('ABSPATH')) {
    exit;
}
// 在设置页测试邮件时使用的 HTML content-type 过滤器（具名，便于移除）
function pcn_admin_html_content_type() {
    return 'text/html';
}

// 在设置页测试邮件时启用 PHPMailer 调试输出（具名，便于移除）
function pcn_admin_debug_hook($phpmailer) {
    $phpmailer->SMTPDebug = 2; // 显示服务器对话
    $phpmailer->Debugoutput = function($str, $level) {
        $line = '[' . gmdate('Y-m-d H:i:s') . ' UTC] level=' . $level . ' ' . $str;
        error_log('pcn SMTP debug: ' . $line);
        // 同时写入 WordPress 选项作为最近日志
        pcn_debug_log_append($line);
    };
}

// 追加一条调试日志到选项（最多保存 500 条）
function pcn_debug_log_append($line) {
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


/**
 * 管理设置页面：SMTP 配置、模板编辑
 */

function pcn_add_admin_menu() {
    add_options_page(
        __('WP Comment Notify', 'wp-comment-notify'),
        __('WP Comment Notify', 'wp-comment-notify'),
        'manage_options',
        'wp-comment-notify',
        'pcn_options_page'
    );
}
add_action('admin_menu', 'pcn_add_admin_menu');

function pcn_register_settings() {
    register_setting('pcn_settings_group', 'pcn_smtp_settings');
    register_setting('pcn_settings_group', 'pcn_templates');
    register_setting('pcn_settings_group', 'pcn_enabled');
    register_setting('pcn_settings_group', 'pcn_license_key');
    register_setting('pcn_settings_group', 'pcn_license_status');
}
add_action('admin_init', 'pcn_register_settings');

function pcn_get_templates_from_files() {
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

function pcn_options_page() {
    if (! current_user_can('manage_options')) {
        return;
    }

    // 处理保存请求
    // 测试发送
    if (isset($_POST['pcn_test_smtp']) && check_admin_referer('pcn_test_smtp')) {
        $test_to = sanitize_email($_POST['test_to'] ?? '');
        if (! empty($test_to)) {
            $subject = __('WP Comment Notify SMTP 测试', 'wp-comment-notify');
            $message = '<p>' . __('这是一封测试邮件，用于验证当前 SMTP/TLS/OAuth 配置是否可用。', 'wp-comment-notify') . '</p>';
            // 启用 HTML 发送（具名过滤器便于移除）
            add_filter('wp_mail_content_type', 'pcn_admin_html_content_type');
            // 仅在本次测试中打开 PHPMailer 的调试输出并写入 error_log（具名，便于移除）
            add_action('phpmailer_init', 'pcn_admin_debug_hook', PHP_INT_MAX);

            $ok = wp_mail($test_to, $subject, $message);

            // 获取 PHPMailer 错误信息
            global $phpmailer;
            $err = '';
            if (is_object($phpmailer) && property_exists($phpmailer, 'ErrorInfo')) {
                $err = trim($phpmailer->ErrorInfo);
                if (! empty($err)) {
                    error_log('pcn: SMTP 测试错误信息: ' . $err);
                }
            }

            // 关闭本次测试的调试钩子与 HTML content-type
            remove_filter('wp_mail_content_type', 'pcn_admin_html_content_type');
            remove_action('phpmailer_init', 'pcn_admin_debug_hook');

            if ($ok) {
                echo '<div class="updated"><p>' . sprintf(__('测试邮件已发送，请检查收件箱：%s', 'wp-comment-notify'), esc_html($test_to)) . '</p></div>';
                if (! empty($err)) {
                    echo '<div class="notice"><p>' . sprintf(__('PHPMailer 提示信息：%s', 'wp-comment-notify'), esc_html($err)) . '</p></div>';
                } else {
                    echo '<div class="notice"><p>' . __('PHPMailer 未返回错误信息。如未收到邮件，请查看服务器日志中以 “pcn SMTP debug” 开头的记录。', 'wp-comment-notify') . '</p></div>';
                }
                // 记录一次当前有效的 SMTP 设置快照，便于对比其他插件
                $snap = get_option('pcn_smtp_settings', array());
                $safeSnap = array(
                    'enable_smtp' => ! empty($snap['enable_smtp']),
                    'host' => $snap['host'] ?? '',
                    'port' => isset($snap['port']) ? intval($snap['port']) : '',
                    'encryption' => $snap['encryption'] ?? '',
                    'smtp_auth' => ! empty($snap['smtp_auth']),
                    'auth_type' => $snap['auth_type'] ?? '',
                    // 不记录敏感的用户名/密码/令牌
                );
                pcn_debug_log_append('[settings-snapshot] ' . wp_json_encode($safeSnap));
            } else {
                $msg = __('测试邮件发送失败。', 'wp-comment-notify');
                if (! empty($err)) {
                    $msg .= ' ' . sprintf(__('错误信息：%s', 'wp-comment-notify'), esc_html($err));
                } else {
                    $msg .= ' ' . __('请检查 SMTP 设置与服务器日志（搜索 “pcn SMTP debug”）。', 'wp-comment-notify');
                }
                echo '<div class="error"><p>' . $msg . '</p></div>';
                // 同步写入错误信息到调试日志
                if (! empty($err)) {
                    pcn_debug_log_append('[ErrorInfo] ' . $err);
                }
                // 失败时同样记录设置快照
                $snap = get_option('pcn_smtp_settings', array());
                $safeSnap = array(
                    'enable_smtp' => ! empty($snap['enable_smtp']),
                    'host' => $snap['host'] ?? '',
                    'port' => isset($snap['port']) ? intval($snap['port']) : '',
                    'encryption' => $snap['encryption'] ?? '',
                    'smtp_auth' => ! empty($snap['smtp_auth']),
                    'auth_type' => $snap['auth_type'] ?? '',
                );
                pcn_debug_log_append('[settings-snapshot] ' . wp_json_encode($safeSnap));
            }
        } else {
            echo '<div class="error"><p>' . __('请填写有效的测试收件人邮箱。', 'wp-comment-notify') . '</p></div>';
        }
    }

    if (isset($_POST['pcn_save_settings']) && check_admin_referer('pcn_save_settings')) {
        // 验证并保存密钥
        $new_key = sanitize_text_field($_POST['pcn_license_key']);
        $old_key = get_option('pcn_license_key');
        $old_status = get_option('pcn_license_status');

        if ($new_key !== $old_key || $old_status !== 'valid') {
            if (empty($new_key)) {
                update_option('pcn_license_key', '');
                update_option('pcn_license_status', 'invalid');
            } else {
                $api_url = base64_decode('aHR0cHM6Ly95YW5xcy5tZS9WZXJpZmljYXRpb24vdmVyaWZ5LnBocD9wYXNzPQ==');
                $response = wp_remote_get($api_url . $new_key);
                if (is_wp_error($response)) {
                    echo '<div class="error"><p>' . sprintf(__('密钥验证请求失败：%s', 'wp-comment-notify'), esc_html($response->get_error_message())) . '</p></div>';
                    update_option('pcn_license_status', 'invalid');
                } else {
                    $body = wp_remote_retrieve_body($response);
                    $data = json_decode($body, true);
                    if (isset($data['status']) && $data['status'] === 'pass') {
                        update_option('pcn_license_key', $new_key);
                        update_option('pcn_license_status', 'valid');
                        echo '<div class="updated"><p>' . __('密钥验证成功！', 'wp-comment-notify') . '</p></div>';
                    } else {
                        update_option('pcn_license_key', $new_key);
                        update_option('pcn_license_status', 'invalid');
                        echo '<div class="error"><p>' . __('密钥无效或已过期。', 'wp-comment-notify') . '</p></div>';
                    }
                }
            }
        }

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
        $smtp['password'] = sanitize_text_field($_POST['password']);
        // 新增独立的发信邮箱与发信名称
        $smtp['from_email'] = sanitize_email($_POST['from_email'] ?? '');
        $smtp['from_name'] = sanitize_text_field($_POST['from_name'] ?? '');
        $smtp['auth_type'] = sanitize_text_field($_POST['auth_type']); // 'login' or 'oauth2'
        $smtp['login_mechanism'] = sanitize_text_field($_POST['login_mechanism'] ?? 'AUTO'); // AUTO, LOGIN or PLAIN
        // 强制使用用户名作为发信地址/Envelope Sender（对某些服务更兼容）
        $smtp['force_from_username'] = ! empty($_POST['force_from_username']) ? 1 : 0;
        // 可选：强制通过 IPv4 连接，规避某些服务对 IPv6 的限制
        $smtp['force_ipv4'] = ! empty($_POST['force_ipv4']) ? 1 : 0;

        $smtp['client_id'] = sanitize_text_field($_POST['client_id']);
        $smtp['client_secret'] = sanitize_text_field($_POST['client_secret']);
        $smtp['refresh_token'] = sanitize_text_field($_POST['refresh_token']);
        update_option('pcn_smtp_settings', $smtp);

        // 模板编辑：优先尝试写入文件，否则保存到 option
        $templates = array();
        $templates['reply'] = wp_kses_post($_POST['tpl_reply']);
        $templates['new_comment'] = wp_kses_post($_POST['tpl_new_comment']);
        $templates['pending'] = wp_kses_post($_POST['tpl_pending']);

        $tpl_dir = PCN_PLUGIN_DIR . 'templates/';
        $can_write = is_writable(PCN_PLUGIN_DIR) || is_writable($tpl_dir);
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

    $smtp = get_option('pcn_smtp_settings', array());
    $enabled = get_option('pcn_enabled', 1);
    $license_key = get_option('pcn_license_key', '');
    $license_status = get_option('pcn_license_status', 'invalid');
    $install_date = get_option('pcn_install_date', time());
    $trial_days = 3;
    $trial_end_time = $install_date + ($trial_days * 86400);
    $is_trial_active = time() < $trial_end_time;
    $is_licensed = $license_status === 'valid';

    // 如果试用期结束且未激活，则强行禁用
    if (!$is_trial_active && !$is_licensed) {
        if ($enabled) {
            update_option('pcn_enabled', 0);
            $enabled = 0;
            echo '<div class="error"><p>' . __('试用期已结束，插件功能已禁用。请输入有效密钥以重新激活。', 'wp-comment-notify') . '</p></div>';
        }
    }

    $saved_templates = get_option('pcn_templates');
    $file_templates = pcn_get_templates_from_files();
    if ($saved_templates && ! empty($saved_templates)) {
        $tpls = wp_parse_args($saved_templates, $file_templates);
    } else {
        $tpls = $file_templates;
    }

    ?>
    <div class="wrap pcn-wrap">
        <style>
            .pcn-wrap { max-width: 1000px; margin: 20px 0; background: #fff; padding: 30px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-radius: 4px; box-sizing: border-box; }
            .pcn-header { border-bottom: 1px solid #eee; padding-bottom: 20px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }
            .pcn-header h1 { margin: 0; padding: 0; font-size: 24px; }
            .pcn-nav-tab-wrapper { border-bottom: 1px solid #c3c4c7; margin-bottom: 20px; padding: 0; }
            .pcn-nav-tab { display: inline-block; padding: 10px 15px; text-decoration: none; color: #2271b1; border: 1px solid transparent; border-bottom: none; margin-bottom: -1px; cursor: pointer; font-weight: 600; font-size: 14px; margin-right: 5px; background: #e5e5e5; border-color: #c3c4c7; }
            .pcn-nav-tab:hover { background: #f0f0f1; color: #0a4b78; }
            .pcn-nav-tab.active { border: 1px solid #c3c4c7; border-bottom-color: #fff; color: #000; background: #fff; }
            .pcn-tab-content { display: none; animation: fadeIn 0.3s; }
            .pcn-tab-content.active { display: block; }
            @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
            .form-table th { width: 220px; font-weight: 600; }
            .pcn-card { background: #fff; border: 1px solid #c3c4c7; padding: 20px; margin-bottom: 20px; border-radius: 0; box-shadow: none; }
            .pcn-card h3 { margin-top: 0; border-bottom: 1px solid #eee; padding-bottom: 10px; margin-bottom: 15px; color: #23282d; }
            .pcn-submit-bar { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; }
            .pcn-status-badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
            .pcn-status-valid { background: #d1e7dd; color: #0f5132; }
            .pcn-status-invalid { background: #f8d7da; color: #842029; }
            .pcn-status-warning { background: #fff3cd; color: #664d03; }
        </style>
        <script>
            jQuery(document).ready(function($) {
                $('.pcn-nav-tab').click(function(e) {
                    e.preventDefault();
                    var target = $(this).data('target');
                    $('.pcn-nav-tab').removeClass('active');
                    $(this).addClass('active');
                    $('.pcn-tab-content').removeClass('active');
                    $('#' + target).addClass('active');
                    localStorage.setItem('pcn_active_tab', target);
                });
                var activeTab = localStorage.getItem('pcn_active_tab');
                if (activeTab && $('#' + activeTab).length) {
                    $('.pcn-nav-tab[data-target="' + activeTab + '"]').click();
                } else {
                    $('.pcn-nav-tab:first').click();
                }

                // 认证类型切换逻辑
                $('#pcn-auth-type-select').change(function() {
                    var type = $(this).val();
                    if (type === 'oauth2') {
                        $('.pcn-auth-login').hide();
                        $('.pcn-auth-oauth2').show();
                    } else {
                        $('.pcn-auth-login').show();
                        $('.pcn-auth-oauth2').hide();
                    }
                }).change(); // 初始化触发
            });
        </script>

        <div class="pcn-header">
            <h1><?php _e('WP Comment & Reply Notify 设置', 'wp-comment-notify'); ?></h1>
            <a href="https://yanqs.me/wp-comment-notify-plugin/" target="_blank" class="button"><?php _e('插件主页', 'wp-comment-notify'); ?></a>
        </div>

        <div class="pcn-nav-tab-wrapper">
            <a href="#" class="pcn-nav-tab active" data-target="tab-general"><?php _e('常规设置', 'wp-comment-notify'); ?></a>
            <a href="#" class="pcn-nav-tab" data-target="tab-smtp"><?php _e('SMTP 设置', 'wp-comment-notify'); ?></a>
            <a href="#" class="pcn-nav-tab" data-target="tab-templates"><?php _e('邮件模板', 'wp-comment-notify'); ?></a>
            <a href="#" class="pcn-nav-tab" data-target="tab-test"><?php _e('测试与日志', 'wp-comment-notify'); ?></a>
        </div>

        <form method="post">
            <?php wp_nonce_field('pcn_save_settings'); ?>

            <div id="tab-general" class="pcn-tab-content active">
                <h2><?php _e('授权与状态', 'wp-comment-notify'); ?></h2>
            <p>
                <a href="https://yanqs.me/wp-comment-notify-plugin/" target="_blank" rel="noopener noreferrer">
                    <?php _e('授权密钥购买', 'wp-comment-notify'); ?>
                </a>
            </p>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php _e('授权密钥', 'wp-comment-notify'); ?></th>
                    <td>
                        <input type="text" name="pcn_license_key" value="<?php echo esc_attr($license_key); ?>" class="regular-text" />
                        <?php if ($is_licensed): ?>
                            <span style="color:green;"><?php _e('有效', 'wp-comment-notify'); ?></span>
                        <?php else: ?>
                            <span style="color:red;"><?php _e('无效', 'wp-comment-notify'); ?></span>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('插件状态', 'wp-comment-notify'); ?></th>
                    <td>
                        <?php
                        if ($is_licensed) {
                            echo '<span style="color:green;font-weight:bold;">' . __('已激活', 'wp-comment-notify') . '</span>';
                        } elseif ($is_trial_active) {
                            $remaining_days = ceil(($trial_end_time - time()) / 86400);
                            echo '<span style="color:orange;font-weight:bold;">' . sprintf(__('试用中，剩余 %d 天', 'wp-comment-notify'), $remaining_days) . '</span>';
                        } else {
                            echo '<span style="color:red;font-weight:bold;">' . __('试用结束，已禁用', 'wp-comment-notify') . '</span>';
                        }
                        ?>
                    </td>
                </tr>
            </table>

            <h2><?php _e('插件总开关', 'wp-comment-notify'); ?></h2>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php _e('启用插件功能', 'wp-comment-notify'); ?></th>
                    <td><input type="checkbox" name="pcn_enabled" value="1" <?php checked(! empty($enabled)); ?> <?php disabled(!$is_licensed && !$is_trial_active); ?> /> <?php _e('启用后才会在评论提交时发送通知邮件。', 'wp-comment-notify'); ?></td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('强制使用用户名作为发信地址', 'wp-comment-notify'); ?></th>
                    <td>
                        <label><input type="checkbox" name="force_from_username" value="1" <?php checked(! empty($smtp['force_from_username'])); ?> /> <?php _e('将 From/Envelope Sender 统一为 SMTP 用户名（某些服务要求二者一致）。', 'wp-comment-notify'); ?></label>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('强制 IPv4 连接', 'wp-comment-notify'); ?></th>
                    <td>
                        <label><input type="checkbox" name="force_ipv4" value="1" <?php checked(! empty($smtp['force_ipv4'])); ?> /> <?php _e('使用 IPv4 连接 SMTP（对 IPv6 报错如 502 Invalid input 时有帮助）。', 'wp-comment-notify'); ?></label>
                    </td>
                </tr>

            </table>
            </div> <!-- End tab-general -->
            <div id="tab-smtp" class="pcn-tab-content">
            <h2><?php _e('SMTP 设置', 'wp-comment-notify'); ?></h2>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php _e('启用 SMTP', 'wp-comment-notify'); ?></th>
                    <td><input type="checkbox" name="enable_smtp" value="1" <?php checked(! empty($smtp['enable_smtp'])); ?> /></td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('主机', 'wp-comment-notify'); ?></th>
                    <td><input type="text" name="host" value="<?php echo esc_attr($smtp['host'] ?? ''); ?>" class="regular-text" /></td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('端口', 'wp-comment-notify'); ?></th>
                    <td><input type="number" name="port" value="<?php echo esc_attr($smtp['port'] ?? 587); ?>" class="small-text" /></td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('加密', 'wp-comment-notify'); ?></th>
                    <td>
                        <select name="encryption">
                            <option value="" <?php selected($smtp['encryption'] ?? '', ''); ?>><?php _e('无', 'wp-comment-notify'); ?></option>
                            <option value="ssl" <?php selected($smtp['encryption'] ?? '', 'ssl'); ?>>SSL</option>
                            <option value="tls" <?php selected($smtp['encryption'] ?? '', 'tls'); ?>>TLS</option>
                        </select>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('需要身份验证', 'wp-comment-notify'); ?></th>
                    <td><input type="checkbox" name="smtp_auth" value="1" <?php checked(! empty($smtp['smtp_auth'])); ?> /></td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('认证类型', 'wp-comment-notify'); ?></th>
                    <td>
                        <select name="auth_type" id="pcn-auth-type-select">
                            <option value="login" <?php selected($smtp['auth_type'] ?? '', 'login'); ?>><?php _e('普通登录 (用户名/密码)', 'wp-comment-notify'); ?></option>
                            <option value="oauth2" <?php selected($smtp['auth_type'] ?? '', 'oauth2'); ?>><?php _e('OAuth2 (若支持)', 'wp-comment-notify'); ?></option>
                        </select>
                        <p class="description"><?php _e('普通登录下可选择具体登录机制（LOGIN/PLAIN）。', 'wp-comment-notify'); ?></p>
                    </td>
                </tr>
                <tr class="pcn-auth-login">
                    <th scope="row"><?php _e('用户名', 'wp-comment-notify'); ?></th>
                    <td><input type="text" name="username" value="<?php echo esc_attr($smtp['username'] ?? ''); ?>" class="regular-text" /></td>
                </tr>
                <tr class="pcn-auth-login">
                    <th scope="row"><?php _e('密码', 'wp-comment-notify'); ?></th>
                    <td><input type="password" name="password" value="<?php echo esc_attr($smtp['password'] ?? ''); ?>" class="regular-text" /></td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('发信邮箱 (From)', 'wp-comment-notify'); ?></th>
                    <td><input type="email" name="from_email" value="<?php echo esc_attr($smtp['from_email'] ?? ''); ?>" class="regular-text" placeholder="no-reply@example.com" />
                        <p class="description"><?php _e('用于邮件的发件人地址（可与 SMTP 用户名不同）。', 'wp-comment-notify'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('发信名称 (From Name)', 'wp-comment-notify'); ?></th>
                    <td><input type="text" name="from_name" value="<?php echo esc_attr($smtp['from_name'] ?? ''); ?>" class="regular-text" placeholder="<?php echo esc_attr(get_bloginfo('name')); ?>" />
                        <p class="description"><?php _e('用于显示在收件人处的发件人名称，留空则使用站点名称。', 'wp-comment-notify'); ?></p>
                    </td>
                </tr>
                <tr class="pcn-auth-login">
                    <th scope="row"><?php _e('登录机制', 'wp-comment-notify'); ?></th>
                    <td>
                        <select name="login_mechanism">
                            <option value="AUTO" <?php selected($smtp['login_mechanism'] ?? 'AUTO', 'AUTO'); ?>><?php _e('自动协商', 'wp-comment-notify'); ?></option>
                            <option value="LOGIN" <?php selected($smtp['login_mechanism'] ?? 'AUTO', 'LOGIN'); ?>>LOGIN</option>
                            <option value="PLAIN" <?php selected($smtp['login_mechanism'] ?? 'AUTO', 'PLAIN'); ?>>PLAIN</option>
                        </select>
                    </td>
                </tr>
                <tr class="pcn-auth-oauth2">
                    <th scope="row">OAuth2 client_id</th>
                    <td><input type="text" name="client_id" value="<?php echo esc_attr($smtp['client_id'] ?? ''); ?>" class="regular-text" /></td>
                </tr>
                <tr class="pcn-auth-oauth2">
                    <th scope="row">OAuth2 client_secret</th>
                    <td><input type="text" name="client_secret" value="<?php echo esc_attr($smtp['client_secret'] ?? ''); ?>" class="regular-text" /></td>
                </tr>
                <tr class="pcn-auth-oauth2">
                    <th scope="row">OAuth2 refresh_token</th>
                    <td><input type="text" name="refresh_token" value="<?php echo esc_attr($smtp['refresh_token'] ?? ''); ?>" class="regular-text" /></td>
                </tr>
                <p><?php _e('注意：OAuth2 认证仅在部分 SMTP 服务（如 Gmail/Google Workspace）支持，且需要预先在对应平台创建应用并获取相关凭据。SMTP 调试成功后请务必删除主题目录下的 smtp_test.php 文件。', 'wp-comment-notify'); ?></p>
            </table>

            </div> <!-- End tab-smtp -->
            <div id="tab-templates" class="pcn-tab-content">
            <h2><?php _e('邮件模板', 'wp-comment-notify'); ?></h2>
            <p><?php _e('编辑 HTML 模板。系统会尝试将更改写入插件的 `templates/` 目录（需可写）。如果写入失败，模板会保存到数据库选项 `pcn_templates`。', 'wp-comment-notify'); ?></p>
            <h3><?php _e('回复通知模板 (reply)', 'wp-comment-notify'); ?></h3>
            <textarea name="tpl_reply" rows="10" style="width:100%;font-family:monospace;"><?php echo esc_textarea($tpls['reply'] ?? ''); ?></textarea>

            <h3><?php _e('管理员新评论通知模板 (new_comment)', 'wp-comment-notify'); ?></h3>
            <textarea name="tpl_new_comment" rows="10" style="width:100%;font-family:monospace;"><?php echo esc_textarea($tpls['new_comment'] ?? ''); ?></textarea>

            <h3><?php _e('待审核通知模板 (pending)', 'wp-comment-notify'); ?></h3>
            <textarea name="tpl_pending" rows="10" style="width:100%;font-family:monospace;"><?php echo esc_textarea($tpls['pending'] ?? ''); ?></textarea>
            
            </div> <!-- End tab-templates -->

            <div class="pcn-submit-bar">
                <input type="submit" name="pcn_save_settings" id="submit" class="button button-primary button-hero" value="<?php esc_attr_e('保存所有设置', 'wp-comment-notify'); ?>" />
            </div>
        </form>

        <div id="tab-test" class="pcn-tab-content">
        <h2><?php _e('SMTP 测试', 'wp-comment-notify'); ?></h2>
        <form method="post">
            <?php wp_nonce_field('pcn_test_smtp'); ?>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php _e('测试收件人邮箱', 'wp-comment-notify'); ?></th>
                    <td><input type="email" name="test_to" value="" class="regular-text" placeholder="you@example.com" /></td>
                </tr>
            </table>
            <p class="submit"><input type="submit" name="pcn_test_smtp" class="button" value="<?php esc_attr_e('发送测试邮件', 'wp-comment-notify'); ?>" /></p>
        </form>

        <hr />
        <h2><?php _e('最近调试日志', 'wp-comment-notify'); ?></h2>
        <form method="post">
            <?php wp_nonce_field('pcn_show_logs'); ?>
            <p>
                <?php _e('显示最近 N 条：', 'wp-comment-notify'); ?>
                <input type="number" name="pcn_logs_n" value="<?php echo isset($_POST['pcn_logs_n']) ? intval($_POST['pcn_logs_n']) : 50; ?>" class="small-text" />
                <input type="submit" name="pcn_show_logs" class="button" value="<?php esc_attr_e('刷新', 'wp-comment-notify'); ?>" />
                <input type="submit" name="pcn_clear_logs" class="button" value="<?php esc_attr_e('清空日志', 'wp-comment-notify'); ?>" />
            </p>
        </form>
        <?php
        // 处理显示/清空日志
        if (isset($_POST['pcn_show_logs']) && check_admin_referer('pcn_show_logs')) {
            $n = isset($_POST['pcn_logs_n']) ? intval($_POST['pcn_logs_n']) : 50;
            $n = max(1, min(500, $n));
            $logs = get_option('pcn_debug_log', array());
            if (! empty($logs)) {
                $show = array_slice($logs, -$n);
                echo '<pre style="max-height:300px;overflow:auto;background:#f7f7f7;padding:10px;border:1px solid #ddd;">';
                foreach ($show as $line) {
                    echo esc_html($line) . "\n";
                }
                echo '</pre>';
            } else {
                echo '<p>' . __('暂无调试日志。', 'wp-comment-notify') . '</p>';
            }
        }
        ?>
        </div> <!-- End tab-test -->
    </div> <!-- End wrap -->
    <?php
        if (isset($_POST['pcn_clear_logs']) && check_admin_referer('pcn_show_logs')) {
            delete_option('pcn_debug_log');
            echo '<div class="updated"><p>' . __('已清空调试日志。', 'wp-comment-notify') . '</p></div>';
        }
    }