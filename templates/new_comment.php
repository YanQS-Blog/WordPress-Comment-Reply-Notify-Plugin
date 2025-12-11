<?php
/**
 * New comment notification template
 * Available variables: author, content, post_title, comment_id, comments_waiting
 */
?>
<div style="background-color: #f0f2f5; padding: 40px 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #3c434a;">
    <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
        <div style="background-color: #2271b1; padding: 24px; text-align: center;">
            <h2 style="margin: 0; font-size: 20px; color: #ffffff; font-weight: 600;">新评论通知</h2>
        </div>
        <div style="padding: 32px;">
            <p style="margin-top: 0; font-size: 16px;">你好，管理员！</p>
            <p style="font-size: 15px; line-height: 1.6;">文章 <strong>《<?php echo esc_html($post_title); ?>》</strong> 收到了新的评论：</p>
            
            <div style="background-color: #f6f7f7; border-left: 4px solid #2271b1; padding: 16px; margin: 20px 0; border-radius: 4px;">
                <div style="font-weight: bold; margin-bottom: 8px; color: #2c3338;"><?php echo esc_html($author); ?> 说：</div>
                <div style="color: #50575e; line-height: 1.6;"><?php echo nl2br($content); ?></div>
            </div>

            <div style="margin-top: 30px; text-align: center;">
                <a href="<?php echo esc_url(admin_url("comment.php?action=approve&c={$comment_id}#wpbody-content")); ?>" style="display: inline-block; background-color: #2271b1; color: #ffffff; text-decoration: none; padding: 10px 20px; border-radius: 4px; font-weight: 500; margin-right: 10px;">批准评论</a>
                <a href="<?php echo esc_url(admin_url("comment.php?action=trash&c={$comment_id}#wpbody-content")); ?>" style="display: inline-block; background-color: #d63638; color: #ffffff; text-decoration: none; padding: 10px 20px; border-radius: 4px; font-weight: 500;">移至回收站</a>
            </div>
        </div>
        <div style="background-color: #f8f9fa; padding: 16px; text-align: center; border-top: 1px solid #e2e4e7;">
            <p style="margin: 0; font-size: 13px; color: #646970;">当前待审核评论数量：<strong><?php echo intval($comments_waiting); ?></strong></p>
        </div>
    </div>
</div>
