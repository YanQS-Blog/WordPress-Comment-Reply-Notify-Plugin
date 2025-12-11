<?php
use PHPUnit\Framework\TestCase;

final class TestEncrypt extends TestCase {
    public function testEncryptDecryptRoundtrip() {
        $plain = 'my-secret-password-123!';
        $enc = PCN_Settings::encrypt_value($plain);
        $this->assertNotEmpty($enc, 'encrypted content should not be empty');
        $dec = PCN_Settings::decrypt_value($enc);
        $this->assertEquals($plain, $dec);
    }

    public function testEncryptEmptyReturnsEmpty() {
        $this->assertEquals('', PCN_Settings::encrypt_value(''));
        $this->assertEquals('', PCN_Settings::decrypt_value(''));
    }
}
