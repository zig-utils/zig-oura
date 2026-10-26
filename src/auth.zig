const std = @import("std");
pub const Key = [16]u8;
pub const Result = enum(u8) { success = 0, rejected = 1, factory_reset = 2, different_onboarded_device = 3, _ };
/// Authenticate an existing pairing. Does not install keys or reset the ring.
pub fn encryptNonce(key: Key, nonce: []const u8) error{InvalidNonce}![16]u8 {
    if (nonce.len != 15) return error.InvalidNonce;
    var block: [16]u8 = undefined;
    @memcpy(block[0..15], nonce);
    block[15] = 1; // AES-128 ECB, one PKCS7-padded block.
    var encrypted: [16]u8 = undefined;
    var aes = std.crypto.core.aes.Aes128.initEnc(key);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&aes));
    aes.encrypt(&encrypted, &block);
    std.crypto.secureZero(u8, &block);
    return encrypted;
}
test "synthetic 15-byte nonce agrees with OpenSSL AES-128 ECB PKCS7" {
    const key: Key = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const expected = [_]u8{ 0xb6, 0x1e, 0x6a, 0xf8, 0xda, 0x72, 0x60, 0xd2, 0x21, 0x43, 0x69, 0xb9, 0x51, 0xbf, 0x89, 0x63 };
    try std.testing.expectEqualSlices(u8, &expected, &(try encryptNonce(key, key[0..15])));
    try std.testing.expectError(error.InvalidNonce, encryptNonce(key, &key));
}
