<?php if (! defined('ABSPATH')) exit; ?>
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

                // 切换到模板标签页时按需初始化 TinyMCE，避免在后台初始化时影响性能
                if (target === 'tab-templates') {
                    if (! window.pcnEditorsInitialized) {
                        // Prefer WP editor initializer when available
                        if (typeof wp !== 'undefined' && wp.editor && typeof wp.editor.initialize === 'function') {
                            ['tpl_reply', 'tpl_new_comment', 'tpl_pending'].forEach(function(id) {
                                if (document.getElementById(id)) {
                                    try {
                                        wp.editor.initialize(id, { tinymce: true, quicktags: false, mediaButtons: false });
                                    } catch (e) {
                                        // ignore init failures
                                    }
                                }
                            });
                        } else if (typeof tinymce !== 'undefined') {
                            // Fallback: initialize editors via tinymce on the textareas
                            ['tpl_reply', 'tpl_new_comment', 'tpl_pending'].forEach(function(id) {
                                var ta = document.getElementById(id);
                                if (ta && ! tinymce.get(id)) {
                                    try {
                                        tinymce.init({ selector: '#' + id, menubar: false });
                                    } catch (e) {
                                        // ignore
                                    }
                                }
                            });
                        }
                        window.pcnEditorsInitialized = true;
                    } else {
                        // 已初始化的编辑器触发重绘，防止渲染高度异常
                        if (typeof tinymce !== 'undefined') {
                            ['tpl_reply', 'tpl_new_comment', 'tpl_pending'].forEach(function(id) {
                                var editor = tinymce.get(id);
                                if (editor && !editor.isHidden()) {
                                    editor.fire('ResizeEditor');
                                }
                            });
                        }
                    }
                }
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
        <a href="#" class="pcn-nav-tab" data-target="tab-test"><?php _e('SMTP 测试', 'wp-comment-notify'); ?></a>
        <a href="#" class="pcn-nav-tab" data-target="tab-logs"><?php _e('发送记录', 'wp-comment-notify'); ?></a>
    </div>

    <form method="post">
        <?php wp_nonce_field('pcn_save_settings'); ?>

        <div id="tab-general" class="pcn-tab-content active">
        <h2><?php _e('插件总开关', 'wp-comment-notify'); ?></h2>
        <table class="form-table">
            <tr>
                <th scope="row"><?php _e('启用插件功能', 'wp-comment-notify'); ?></th>
                <td><input type="checkbox" name="pcn_enabled" value="1" <?php checked(! empty($enabled)); ?> /> <?php _e('启用后才会在评论提交时发送通知邮件。', 'wp-comment-notify'); ?></td>
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
                <td>
                    <input type="password" name="password" value="" class="regular-text" />
                    <p class="description"><?php _e('为安全起见，此处不回显保存的密码。若需通过环境变量提供，请在 wp-config.php 中定义 `PCN_SMTP_PASSWORD`。', 'wp-comment-notify'); ?></p>
                </td>
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
                <td>
                    <input type="text" name="client_secret" value="" class="regular-text" />
                    <p class="description"><?php _e('客户端密钥不会明文回显。可在 wp-config.php 中定义 `PCN_SMTP_CLIENT_SECRET`，或在此处填写并保存（会以加密形式存储）。', 'wp-comment-notify'); ?></p>
                </td>
            </tr>
            <tr class="pcn-auth-oauth2">
                <th scope="row">OAuth2 refresh_token</th>
                <td>
                    <input type="text" name="refresh_token" value="" class="regular-text" />
                    <p class="description"><?php _e('出于安全考虑，刷新令牌不会明文回显。可在 wp-config.php 中定义 `PCN_SMTP_REFRESH_TOKEN`，或在此处填写并保存（会以加密形式存储）。', 'wp-comment-notify'); ?></p>
                </td>
            </tr>
            <p><?php _e('注意：OAuth2 认证仅在部分 SMTP 服务（如 Gmail/Google Workspace）支持，且需要预先在对应平台创建应用并获取相关凭据。SMTP 调试成功后请务必删除主题目录下的 smtp_test.php 文件。', 'wp-comment-notify'); ?></p>
        </table>

        </div> <!-- End tab-smtp -->
        <div id="tab-templates" class="pcn-tab-content">
        <h2><?php _e('邮件模板', 'wp-comment-notify'); ?></h2>
        <p><?php _e('编辑 HTML 模板。系统会尝试将更改写入插件的 `templates/` 目录（需可写）。如果写入失败，模板会保存到数据库选项 `pcn_templates`。', 'wp-comment-notify'); ?></p>
        <h3><?php _e('回复通知模板 (reply)', 'wp-comment-notify'); ?></h3>
        <p class="description"><?php _e('可用变量：{{blogname}}, {{parent_author}}, {{parent_content}}, {{reply_author}}, {{reply_content}}, {{comment_link}}, {{unsubscribe_url}}', 'wp-comment-notify'); ?></p>
        <?php wp_editor($tpls['reply'] ?? '', 'tpl_reply', array('textarea_name' => 'tpl_reply', 'textarea_rows' => 15, 'media_buttons' => false, 'tinymce' => false)); ?>

        <h3><?php _e('管理员新评论通知模板 (new_comment)', 'wp-comment-notify'); ?></h3>
        <p class="description"><?php _e('可用变量：{{author}}, {{content}}, {{post_title}}, {{comment_id}}, {{comments_waiting}}, {{approve_url}}, {{trash_url}}, {{spam_url}}', 'wp-comment-notify'); ?></p>
        <?php wp_editor($tpls['new_comment'] ?? '', 'tpl_new_comment', array('textarea_name' => 'tpl_new_comment', 'textarea_rows' => 15, 'media_buttons' => false, 'tinymce' => false)); ?>

        <h3><?php _e('待审核通知模板 (pending)', 'wp-comment-notify'); ?></h3>
        <p class="description"><?php _e('可用变量：{{author}}, {{content}}, {{post_title}}, {{comment_id}}, {{comments_waiting}}, {{approve_url}}, {{trash_url}}, {{spam_url}}', 'wp-comment-notify'); ?></p>
        <?php wp_editor($tpls['pending'] ?? '', 'tpl_pending', array('textarea_name' => 'tpl_pending', 'textarea_rows' => 15, 'media_buttons' => false, 'tinymce' => false)); ?>
        
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
            <p class="submit">
                <input type="submit" name="pcn_test_smtp" class="button" value="<?php esc_attr_e('发送测试邮件', 'wp-comment-notify'); ?>" />
                <input type="submit" name="pcn_clear_debug_logs" class="button" value="<?php esc_attr_e('清空调试日志', 'wp-comment-notify'); ?>" />
            </p>
        </form>

        <?php if (! empty($debug_logs)): ?>
            <h3><?php _e('SMTP 调试日志', 'wp-comment-notify'); ?></h3>
            <pre style="max-height:300px;overflow:auto;background:#f7f7f7;padding:10px;border:1px solid #ddd;"><?php
                foreach ($debug_logs as $line) {
                    echo esc_html($line) . "\n";
                }
            ?></pre>
        <?php endif; ?>
    </div> <!-- End tab-test -->

    <div id="tab-logs" class="pcn-tab-content">
        <h2><?php _e('邮件发送记录', 'wp-comment-notify'); ?></h2>
        <form method="post">
            <?php wp_nonce_field('pcn_show_logs'); ?>
            <p>
                <?php _e('显示最近 N 条：', 'wp-comment-notify'); ?>
                <input type="number" name="pcn_logs_n" value="<?php echo isset($_POST['pcn_logs_n']) ? intval($_POST['pcn_logs_n']) : 50; ?>" class="small-text" />
                <input type="submit" name="pcn_show_logs" class="button" value="<?php esc_attr_e('刷新', 'wp-comment-notify'); ?>" />
                <input type="submit" name="pcn_clear_logs" class="button" value="<?php esc_attr_e('清空日志', 'wp-comment-notify'); ?>" />
            </p>
        </form>
        <table class="widefat fixed striped">
            <thead>
                <tr>
                    <th style="width: 160px;"><?php _e('时间', 'wp-comment-notify'); ?></th>
                    <th><?php _e('收件人', 'wp-comment-notify'); ?></th>
                    <th><?php _e('主题', 'wp-comment-notify'); ?></th>
                    <th style="width: 80px;"><?php _e('状态', 'wp-comment-notify'); ?></th>
                    <th><?php _e('错误信息', 'wp-comment-notify'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php if ($logs_to_show && !empty($logs_to_show)): ?>
                    <?php foreach ($logs_to_show as $log): ?>
                        <tr>
                            <td><?php echo esc_html($log['time']); ?></td>
                            <td><?php echo esc_html($log['to']); ?></td>
                            <td><?php echo esc_html($log['subject']); ?></td>
                            <td>
                                <?php if ($log['status'] === 'success'): ?>
                                    <span style="color: green;"><?php _e('成功', 'wp-comment-notify'); ?></span>
                                <?php else: ?>
                                    <span style="color: red;"><?php _e('失败', 'wp-comment-notify'); ?></span>
                                <?php endif; ?>
                            </td>
                            <td><?php echo esc_html($log['error']); ?></td>
                        </tr>
                    <?php endforeach; ?>
                <?php else: ?>
                    <tr>
                        <td colspan="5"><?php _e('暂无记录。', 'wp-comment-notify'); ?></td>
                    </tr>
                <?php endif; ?>
            </tbody>
        </table>
    </div> <!-- End tab-logs -->
</div> <!-- End wrap -->
