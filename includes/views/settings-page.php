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
        <div id="pcn-ajax-result"></div>

        <div id="tab-general" class="pcn-tab-content active">
        <h2><?php _e('插件总开关', 'wp-comment-notify'); ?></h2>
        <div class="pcn-card" id="pcn-dashboard">
            <h3><?php _e('仪表盘与统计', 'wp-comment-notify'); ?></h3>
            <div style="display:flex;gap:16px;margin-bottom:12px;align-items:center;">
                <div style="flex:0 0 160px;padding:12px;border:1px solid #e1e1e1;border-radius:6px;background:#fff;">
                    <div style="font-size:12px;color:#666"><?php _e('已发送（成功）', 'wp-comment-notify'); ?></div>
                    <div id="pcn-total-success" style="font-size:20px;font-weight:700;margin-top:6px;">—</div>
                </div>
                <div style="flex:0 0 160px;padding:12px;border:1px solid #e1e1e1;border-radius:6px;background:#fff;">
                    <div style="font-size:12px;color:#666"><?php _e('发送失败', 'wp-comment-notify'); ?></div>
                    <div id="pcn-total-failure" style="font-size:20px;font-weight:700;margin-top:6px;color:#c0392b;">—</div>
                </div>
                <div style="flex:0 0 160px;padding:12px;border:1px solid #e1e1e1;border-radius:6px;background:#fff;">
                    <div style="font-size:12px;color:#666"><?php _e('退订数', 'wp-comment-notify'); ?></div>
                    <div id="pcn-total-unsub" style="font-size:20px;font-weight:700;margin-top:6px;color:#666;">—</div>
                </div>
                <div style="margin-left:auto;display:flex;gap:8px;align-items:center;">
                    <select id="pcn-stats-days" style="padding:6px;border:1px solid #ccc;border-radius:4px;">
                        <option value="7">7 <?php _e('天', 'wp-comment-notify'); ?></option>
                        <option value="14">14 <?php _e('天', 'wp-comment-notify'); ?></option>
                        <option value="30">30 <?php _e('天', 'wp-comment-notify'); ?></option>
                    </select>
                    <button type="button" id="pcn-refresh-stats" class="button"><?php esc_html_e('刷新', 'wp-comment-notify'); ?></button>
                </div>
            </div>
            <div>
                <canvas id="pcn-stats-chart" width="800" height="200" style="max-width:100%;height:200px;"></canvas>
            </div>
        </div>
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
            <p style="margin-top:15px;">
                <button type="submit" name="pcn_clear_credentials" class="button" onclick="return confirm('<?php echo esc_js( __( '确定要清除所有已保存的敏感凭据吗？推荐通过环境变量提供凭据。', 'wp-comment-notify' ) ); ?>');"><?php esc_html_e('清除凭据', 'wp-comment-notify'); ?></button>
                <?php wp_nonce_field('pcn_clear_credentials', 'pcn_clear_credentials_nonce'); ?>
            </p>
            <p style="margin-top:8px;">
                <button type="button" class="button button-secondary" id="pcn-run-diagnostics"><?php _e('运行 SMTP 诊断', 'wp-comment-notify'); ?></button>
            </p>
            <div id="pcn-diagnostics-result" style="margin-top:8px;color:#444"></div>
            <h3 style="margin-top:20px;"><?php _e('邮件队列设置', 'wp-comment-notify'); ?></h3>
            <p class="description"><?php _e('启用异步邮件队列以减少请求阻塞并支持重试/重试退避。', 'wp-comment-notify'); ?></p>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php _e('启用队列', 'wp-comment-notify'); ?></th>
                    <td><label><input type="checkbox" name="pcn_queue_enabled" value="1" <?php checked(! empty($smtp_options['queue_enabled'])); ?> /> <?php _e('启用异步队列（推荐）', 'wp-comment-notify'); ?></label></td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('批次大小', 'wp-comment-notify'); ?></th>
                    <td><input type="number" name="pcn_queue_batch" value="<?php echo esc_attr($smtp_options['queue_batch'] ?? 10); ?>" class="small-text" /> <span class="description"><?php _e('每次处理队列的最大邮件数。', 'wp-comment-notify'); ?></span></td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('最大重试次数', 'wp-comment-notify'); ?></th>
                    <td><input type="number" name="pcn_queue_retries" value="<?php echo esc_attr($smtp_options['queue_retries'] ?? 5); ?>" class="small-text" /> <span class="description"><?php _e('超过次数后将放弃并记录错误。', 'wp-comment-notify'); ?></span></td>
                </tr>
                <tr>
                    <th scope="row"><?php _e('队列操作', 'wp-comment-notify'); ?></th>
                    <td>
                        <input type="submit" name="pcn_process_queue" class="button" value="<?php esc_attr_e('立即处理队列', 'wp-comment-notify'); ?>" />
                        &nbsp;
                        <input type="submit" name="pcn_clear_queue" class="button" onclick="return confirm('<?php echo esc_js( __( '确定要清空邮件队列吗？此操作不可恢复。', 'wp-comment-notify' ) ); ?>');" value="<?php esc_attr_e('清空队列', 'wp-comment-notify'); ?>" />
                        <?php if (! empty($queue_count)): ?>
                            <p class="description"><?php printf(__('当前队列中有 %d 条待发送邮件。', 'wp-comment-notify'), intval($queue_count)); ?></p>
                        <?php endif; ?>
                        <p>
                            <button type="button" id="pcn-refresh-queue" class="button"><?php esc_html_e('刷新队列状态', 'wp-comment-notify'); ?></button>
                        </p>
                        <div id="pcn-queue-status" style="margin-top:10px;">
                            <strong><?php _e('最近队列处理记录：', 'wp-comment-notify'); ?></strong>
                            <div id="pcn-queue-actions" style="max-height:200px;overflow:auto;background:#f7f7f7;padding:8px;border:1px solid #ddd;margin-top:8px;"></div>
                        </div>
                    </td>
                </tr>
            </table>
            <script>
                (function($){
                    var ajaxurl = '<?php echo admin_url('admin-ajax.php'); ?>';
                    var nonce = '<?php echo esc_js($queue_nonce); ?>';
                    function renderActions(actions){
                        var html = '';
                        if (!actions || actions.length === 0) {
                            html = '<div><?php esc_html_e('暂无队列处理记录。', 'wp-comment-notify'); ?></div>';
                        } else {
                            actions.slice().reverse().forEach(function(a){
                                html += '<div style="border-bottom:1px solid #eee;padding:6px 0;">';
                                html += '<div style="font-size:12px;color:#666;">' + a.time + ' — ' + escHtml(a.result) + '</div>';
                                html += '<div><strong>' + escHtml(a.to) + '</strong> &nbsp; ' + escHtml(a.subject) + '</div>';
                                if (a.error) { html += '<div style="color:#a00;font-size:12px;">' + escHtml(a.error) + '</div>'; }
                                html += '</div>';
                            });
                        }
                        $('#pcn-queue-actions').html(html);
                    }
                    function escHtml(s){ return String(s).replace(/[&<>"']/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); }
                    $('#pcn-refresh-queue').on('click', function(){
                        $.post(ajaxurl, { action: 'pcn_get_queue_status', nonce: nonce }, function(res){
                            if (res.success) {
                                renderActions(res.data.recent_actions);
                            } else {
                                alert('<?php echo esc_js(__('错误', 'wp-comment-notify')); ?>');
                            }
                        });
                    });
                    $('#pcn-refresh-queue').trigger('click');
                    // Process queue via AJAX
                    $('input[name="pcn_process_queue"]').on('click', function(e){
                        e.preventDefault();
                        $.post(ajaxurl, { action: 'pcn_process_queue', nonce: nonce }, function(res){
                            if (res.success) {
                                renderActions(res.data.recent_actions);
                                alert('<?php echo esc_js( __( '队列已处理，已更新记录。', 'wp-comment-notify' ) ); ?>');
                            } else {
                                alert('<?php echo esc_js(__('错误', 'wp-comment-notify')); ?>');
                            }
                        });
                    });
                    // Clear queue via AJAX
                    $('input[name="pcn_clear_queue"]').on('click', function(e){
                        if (! confirm('<?php echo esc_js( __( '确定要清空邮件队列吗？此操作不可恢复。', 'wp-comment-notify' ) ); ?>')) { return false; }
                        e.preventDefault();
                        $.post(ajaxurl, { action: 'pcn_clear_queue', nonce: nonce }, function(res){
                            if (res.success) {
                                renderActions([]);
                                alert('<?php echo esc_js( __( '邮件队列已清空。', 'wp-comment-notify' ) ); ?>');
                            } else {
                                alert('Error');
                            }
                        });
                    });
                })(jQuery);
            </script>
            <script>
            jQuery(function($){
                $('#pcn-run-diagnostics').on('click', function(e){
                    e.preventDefault();
                    var $btn = $(this).prop('disabled', true).text('<?php echo esc_js(__('运行中...', 'wp-comment-notify')); ?>');
                    var nonce = '<?php echo esc_js(wp_create_nonce('pcn_diagnostics')); ?>';
                    $.post(ajaxurl, { action: 'pcn_run_diagnostics', nonce: nonce }, function(resp){
                        $btn.prop('disabled', false).text('<?php echo esc_js(__('运行 SMTP 诊断', 'wp-comment-notify')); ?>');
                        if (resp.success) {
                            var r = resp.data;
                            var html = [];
                            html.push('<strong><?php echo esc_js(__('Host', 'wp-comment-notify')); ?>:</strong> ' + (r.host_resolution.msg || ''));
                            html.push('<br><strong><?php echo esc_js(__('Connect', 'wp-comment-notify')); ?>:</strong> ' + (r.connect.msg || ''));
                            html.push('<br><strong><?php echo esc_js(__('MX', 'wp-comment-notify')); ?>:</strong> ' + (r.mx.msg || ''));
                            html.push('<br><strong><?php echo esc_js(__('SPF', 'wp-comment-notify')); ?>:</strong> ' + (r.spf.msg || ''));
                            if (r.certificate && r.certificate.msg) {
                                html.push('<br><strong><?php echo esc_js(__('Certificate', 'wp-comment-notify')); ?>:</strong> ' + r.certificate.msg);
                            }
                            $('#pcn-diagnostics-result').html(html.join(''));
                        } else {
                            $('#pcn-diagnostics-result').text('<?php echo esc_js(__('诊断失败', 'wp-comment-notify')); ?>');
                        }
                    }, 'json').fail(function(){
                        $btn.prop('disabled', false).text('<?php echo esc_js(__('运行 SMTP 诊断', 'wp-comment-notify')); ?>');
                        $('#pcn-diagnostics-result').text('<?php echo esc_js(__('请求失败', 'wp-comment-notify')); ?>');
                    });
                });
            });
            </script>
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

    <div id="tab-test" class="pcn-tab-content">
        <h2><?php _e('SMTP 测试', 'wp-comment-notify'); ?></h2>
        <?php wp_nonce_field('pcn_test_smtp', 'pcn_test_smtp_nonce'); ?>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php _e('测试收件人邮箱', 'wp-comment-notify'); ?></th>
                    <td><input type="email" name="test_to" value="" class="regular-text" placeholder="you@example.com" /></td>
                </tr>
            </table>
            <p class="submit">
                <input type="submit" name="pcn_test_smtp" class="button" value="<?php esc_attr_e('发送测试邮件', 'wp-comment-notify'); ?>" />
            </p>
        

        <h3><?php _e('SMTP 调试日志', 'wp-comment-notify'); ?></h3>
        <p>
            <button type="button" id="pcn-load-debug-logs" class="button"><?php esc_html_e('加载调试日志', 'wp-comment-notify'); ?></button>
            <input type="submit" name="pcn_clear_debug_logs" class="button" value="<?php esc_attr_e('清空调试日志', 'wp-comment-notify'); ?>" />
            <span class="description"><?php _e('发送测试邮件后会自动加载最新的调试日志。', 'wp-comment-notify'); ?></span>
        </p>
        <pre id="pcn-debug-logs" style="display:none;max-height:300px;overflow:auto;background:#f7f7f7;padding:10px;border:1px solid #ddd;"></pre>
    </div> <!-- End tab-test -->

    <div id="tab-logs" class="pcn-tab-content">
        <h2><?php _e('邮件发送记录', 'wp-comment-notify'); ?></h2>
        <?php wp_nonce_field('pcn_show_logs', 'pcn_show_logs_nonce'); ?>
            <p>
                <?php _e('显示最近 N 条：', 'wp-comment-notify'); ?>
                <input type="number" id="pcn_logs_n" name="pcn_logs_n" value="<?php echo isset($_POST['pcn_logs_n']) ? intval($_POST['pcn_logs_n']) : 50; ?>" class="small-text" />
                <button type="button" id="pcn-refresh-logs-ajax" class="button"><?php esc_html_e('刷新', 'wp-comment-notify'); ?></button>
                <input type="submit" name="pcn_clear_logs" class="button" value="<?php esc_attr_e('清空日志', 'wp-comment-notify'); ?>" />
            </p>

            <h3><?php _e('导出与保留策略', 'wp-comment-notify'); ?></h3>
            <p>
                <?php _e('导出最近 N 天的日志为 CSV（填 0 导出全部）：', 'wp-comment-notify'); ?>
                <input type="number" name="pcn_export_days" value="0" class="small-text" />
                <input type="submit" name="pcn_export_logs" class="button" value="<?php esc_attr_e('导出 CSV', 'wp-comment-notify'); ?>" />
            </p>
            <p>
                <?php _e('设置保留策略：删除早于 N 天的日志（谨慎操作）：', 'wp-comment-notify'); ?>
                <input type="number" name="pcn_retention_days" value="90" class="small-text" />
                <input type="submit" name="pcn_set_retention" class="button" value="<?php esc_attr_e('应用保留策略', 'wp-comment-notify'); ?>" />
            </p>
        <table class="widefat fixed striped" id="pcn-logs-table">
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
        <script>
        jQuery(function($){
            var ajaxurl = '<?php echo admin_url('admin-ajax.php'); ?>';
            var statsNonce = '<?php echo esc_js(wp_create_nonce('pcn_stats')); ?>';
            var $form = $('.pcn-wrap > form');
            // Load debug logs button
            $('#pcn-load-debug-logs').on('click', function(){
                var $btn = $(this).prop('disabled', true);
                var nonce = ($('[name="pcn_test_smtp_nonce"]').length) ? $('[name="pcn_test_smtp_nonce"]').val() : '';
                $.post(ajaxurl, { action: 'pcn_load_debug_logs', nonce: nonce }, function(res){
                    $btn.prop('disabled', false);
                    if (res.success) {
                        var logs = res.data.logs || [];
                        $('#pcn-debug-logs').text(logs.join('\n')).show();
                    } else {
                        alert('<?php echo esc_js(__('加载失败', 'wp-comment-notify')); ?>');
                    }
                }, 'json').fail(function(){ $btn.prop('disabled', false); alert('<?php echo esc_js(__('请求失败', 'wp-comment-notify')); ?>'); });
            });
            // Clear debug logs via AJAX (no page reload)
            $('input[name="pcn_clear_debug_logs"]').on('click', function(e){
                e.preventDefault();
                var $btn = $(this).prop('disabled', true);
                var nonce = ($('[name="pcn_test_smtp_nonce"]').length) ? $('[name="pcn_test_smtp_nonce"]').val() : '';
                $.post(ajaxurl, { action: 'pcn_clear_debug_logs', nonce: nonce }, function(res){
                    $btn.prop('disabled', false);
                    if (res.success) {
                        $('#pcn-debug-logs').text('').hide();
                        // show a brief notice in the ajax result area
                        $('#pcn-ajax-result').html('<div class="updated"><p>' + '<?php echo esc_js(__('已清空 SMTP 调试日志。', 'wp-comment-notify')); ?>' + '</p></div>');
                    } else {
                        alert('<?php echo esc_js(__('清空失败', 'wp-comment-notify')); ?>');
                    }
                }, 'json').fail(function(){ $btn.prop('disabled', false); alert('<?php echo esc_js(__('请求失败', 'wp-comment-notify')); ?>'); });
            });
            // Ensure an invisible iframe exists for background CSV download
            if (!$('#pcn-export-iframe').length) {
                $('<iframe id="pcn-export-iframe" name="pcn-export-iframe" style="display:none"></iframe>').appendTo('body');
            }
            // When export button is clicked, submit the form targeting the hidden iframe
            $form.on('click', 'input[name="pcn_export_logs"]', function(){
                var originalAction = $form.attr('action') || '';
                // Post to admin-post to return a downloadable CSV
                $form.attr('action', '<?php echo esc_js(admin_url('admin-post.php')); ?>?action=pcn_export_logs');
                $form.attr('target', 'pcn-export-iframe');
                // Restore original action/target shortly after
                setTimeout(function(){ $form.removeAttr('target'); if (originalAction) { $form.attr('action', originalAction); } else { $form.removeAttr('action'); } }, 3000);
            });
            // Intercept clicks only on submit buttons inside main form
            $form.on('click', 'input[type=submit], button[type=submit]', function(e){
                var $btn = $(this);
                // let dedicated handlers run (diagnostics, queue refresh, logs refresh)
                // Also allow the Export CSV submit to perform a normal form submit (returns a CSV response)
                if ($btn.is('#pcn-run-diagnostics') || $btn.is('#pcn-refresh-queue') || $btn.is('#pcn-refresh-logs-ajax') || $btn.attr('name') === 'pcn_export_logs') {
                    return;
                }
                e.preventDefault();
                var data = $form.serializeArray();
                // include secondary nonces that may live outside the main form
                var extraNonces = ['pcn_test_smtp_nonce','pcn_clear_credentials_nonce','pcn_show_logs_nonce'];
                extraNonces.forEach(function(n){
                    var $f = $("[name='"+n+"']");
                    if ($f.length) {
                        data.push({ name: n, value: $f.val() });
                    }
                });
                if ($btn.attr('name')) {
                    data.push({ name: $btn.attr('name'), value: $btn.val() });
                } else if ($btn.attr('id')) {
                    data.push({ name: $btn.attr('id'), value: $btn.text() });
                }
                data.push({ name: 'action', value: 'pcn_ajax_form' });

                $btn.prop('disabled', true);
                $.post(ajaxurl, data, function(resp){
                    $btn.prop('disabled', false);
                    if (resp.success) {
                        if (resp.data.html) {
                            $('#pcn-ajax-result').html(resp.data.html);
                        }
                        if (resp.data.extra && resp.data.extra.logs) {
                            var rows = resp.data.extra.logs;
                            var html = '';
                            if (!rows || rows.length === 0) {
                                html = '<tr><td colspan="5"><?php echo esc_js(__('暂无记录。', 'wp-comment-notify')); ?></td></tr>';
                            } else {
                                rows.forEach(function(r){
                                    html += '<tr>';
                                    html += '<td>' + (r.time || '') + '</td>';
                                    html += '<td>' + $('<div/>').text(r.to || '').html() + '</td>';
                                    html += '<td>' + $('<div/>').text(r.subject || '').html() + '</td>';
                                    html += '<td>' + (r.status === 'success' ? '<span style="color:green;">' + '<?php echo esc_js(__("成功", "wp-comment-notify")); ?>' + '</span>' : '<span style="color:red;">' + '<?php echo esc_js(__("失败", "wp-comment-notify")); ?>' + '</span>') + '</td>';
                                    html += '<td>' + $('<div/>').text(r.error || '').html() + '</td>';
                                    html += '</tr>';
                                });
                            }
                            $('#pcn-logs-table tbody').html(html);
                        }
                        // If server returned debug logs (e.g., after test email), show them
                        if (resp.data.extra && resp.data.extra.debug_logs) {
                            var dbg = resp.data.extra.debug_logs || [];
                            $('#pcn-debug-logs').text(dbg.join('\n')).show();
                        }
                    } else {
                        alert('<?php echo esc_js(__('请求失败', 'wp-comment-notify')); ?>');
                    }
                    }, 'json').fail(function(){
                        $btn.prop('disabled', false);
                        alert('<?php echo esc_js(__('请求失败', 'wp-comment-notify')); ?>');
                    });
            });

            // Dashboard: load stats and render chart
            function loadStats(days) {
                days = days || parseInt($('#pcn-stats-days').val()) || 7;
                $.post(ajaxurl, { action: 'pcn_get_stats', days: days, nonce: statsNonce }, function(res){
                    if (! res.success) { return; }
                    var d = res.data;
                    $('#pcn-total-success').text(d.totals.success);
                    $('#pcn-total-failure').text(d.totals.failure);
                    $('#pcn-total-unsub').text(d.unsubscribes);
                    renderStatsChart(d.labels, d.success, d.failure);
                }, 'json');
            }

            function renderStatsChart(labels, successData, failureData) {
                // load Chart.js if not present
                function doRender() {
                    var ctx = document.getElementById('pcn-stats-chart').getContext('2d');
                    if (window._pcn_stats_chart) { window._pcn_stats_chart.destroy(); }
                    window._pcn_stats_chart = new Chart(ctx, {
                        type: 'line',
                        data: {
                            labels: labels,
                            datasets: [
                                { label: '<?php echo esc_js(__('成功', 'wp-comment-notify')); ?>', data: successData, borderColor: 'green', backgroundColor: 'rgba(0,128,0,0.08)', fill: true },
                                { label: '<?php echo esc_js(__('失败', 'wp-comment-notify')); ?>', data: failureData, borderColor: 'red', backgroundColor: 'rgba(255,0,0,0.06)', fill: true }
                            ]
                        },
                        options: { responsive: true, maintainAspectRatio: false }
                    });
                }
                if (typeof Chart === 'undefined') {
                    var s = document.createElement('script');
                    s.src = 'https://cdn.jsdelivr.net/npm/chart.js';
                    s.onload = doRender;
                    document.head.appendChild(s);
                } else {
                    doRender();
                }
            }

            // init dashboard
            $('#pcn-refresh-stats').on('click', function(){ loadStats(); });
            loadStats();
        });
        </script>
    </form>
        <script>
            jQuery(function($){
                var ajaxurl = '<?php echo admin_url('admin-ajax.php'); ?>';
                $('#pcn-refresh-logs-ajax').on('click', function(){
                    var n = parseInt($('#pcn_logs_n').val()) || 50;
                    var nonce = '<?php echo esc_js(wp_create_nonce('pcn_show_logs')); ?>';
                    var $btn = $(this).prop('disabled', true).text('<?php echo esc_js(__('刷新中...', 'wp-comment-notify')); ?>');
                    $.post(ajaxurl, { action: 'pcn_refresh_logs', nonce: nonce, n: n }, function(resp){
                        $btn.prop('disabled', false).text('<?php echo esc_js(__('刷新', 'wp-comment-notify')); ?>');
                        if (resp.success) {
                            var rows = resp.data.rows || [];
                            var html = '';
                            if (rows.length === 0) {
                                html = '<tr><td colspan="5"><?php echo esc_js(__('暂无记录。', 'wp-comment-notify')); ?></td></tr>';
                            } else {
                                rows.forEach(function(r){
                                    html += '<tr>';
                                    html += '<td>' + (r.time || '') + '</td>';
                                    html += '<td>' + $('<div/>').text(r.to || '').html() + '</td>';
                                    html += '<td>' + $('<div/>').text(r.subject || '').html() + '</td>';
                                    html += '<td>' + (r.status === 'success' ? '<span style="color:green;"><?php echo esc_js(__('成功', 'wp-comment-notify')); ?></span>' : '<span style="color:red;"><?php echo esc_js(__('失败', 'wp-comment-notify')); ?></span>') + '</td>';
                                    html += '<td>' + $('<div/>').text(r.error || '').html() + '</td>';
                                    html += '</tr>';
                                });
                            }
                            $('#pcn-logs-table tbody').html(html);
                        } else {
                            alert('<?php echo esc_js(__('刷新失败', 'wp-comment-notify')); ?>');
                        }
                    }, 'json').fail(function(){
                        $btn.prop('disabled', false).text('<?php echo esc_js(__('刷新', 'wp-comment-notify')); ?>');
                        alert('<?php echo esc_js(__('请求失败', 'wp-comment-notify')); ?>');
                    });
                });
            });
        </script>
    </div> <!-- End tab-logs -->
</div> <!-- End wrap -->
