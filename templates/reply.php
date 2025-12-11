<?php
/**
 * Reply notification template
 * Available variables: blogname, parent_author, parent_content, reply_author, reply_content, comment_link
 */
?>
<div style="background-color: #f0f2f5; padding: 40px 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #3c434a;">
    <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
        <div style="background-color: #2271b1; padding: 24px; text-align: center;">
            <h2 style="margin: 0; font-size: 20px; color: #ffffff; font-weight: 600;">新回复通知</h2>
        </div>
        <div style="padding: 32px;">
            <p style="margin-top: 0; font-size: 16px;">你好，<strong><?php echo esc_html($parent_author); ?></strong>！</p>
            <p style="font-size: 15px; line-height: 1.6;">您在 <strong><?php echo esc_html($blogname); ?></strong> 的评论收到了新的回复。</p>
            
            <div style="margin-top: 24px;">
                <p style="font-size: 14px; color: #646970; margin-bottom: 8px;">您的原评论：</p>
                <div style="background-color: #f0f0f1; padding: 16px; border-radius: 4px; color: #50575e; line-height: 1.6; font-style: italic;">
                    <?php echo nl2br($parent_content); ?>
                </div>
            </div>

            <div style="margin-top: 24px;">
                <p style="font-size: 14px; color: #646970; margin-bottom: 8px;"><strong><?php echo esc_html($reply_author); ?></strong> 的回复：</p>
                <div style="background-color: #f6f7f7; border-left: 4px solid #2271b1; padding: 16px; border-radius: 4px; color: #2c3338; line-height: 1.6;">
                    <?php echo nl2br($reply_content); ?>
                </div>
            </div>

            <div style="margin-top: 30px; text-align: center;">
                <a href="<?php echo esc_url($comment_link); ?>" style="display: inline-block; background-color: #2271b1; color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 4px; font-weight: 500;">查看完整回复</a>
            </div>
        </div>
        <div style="background-color: #f8f9fa; padding: 16px; text-align: center; border-top: 1px solid #e2e4e7;">
            <p style="margin: 0; font-size: 12px; color: #8c8f94;">此邮件由系统自动发送，请勿直接回复。</p>
        </div>
    </div>
</div>
