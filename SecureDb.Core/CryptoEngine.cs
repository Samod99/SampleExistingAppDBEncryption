using System;
using System.Security.Cryptography;
using System.Text;

namespace SecureDb.Core
{
    public enum EncryptionMode
    {
        Random,
        Deterministic
    }

    /// <summary>
    /// AES-256-GCM based field encryption.
    ///
    /// ⚠️ BREAKING FORMAT CHANGE from the earlier version of this file: the ciphertext
    /// package now embeds a format version and a KEY VERSION NUMBER in its header, so that
    /// key rotation can work correctly (an old row can be decrypted with the key version it
    /// was actually encrypted under, even after the key has been rotated to a newer version).
    ///
    /// Any data already encrypted with the OLD format (plain [nonce][ciphertext][tag], no
    /// header) will NOT decrypt correctly under this version — the header bytes will be
    /// misread as part of the nonce. If you have test rows encrypted with the previous
    /// version of this file, delete/re-insert them after upgrading, rather than trying to
    /// read them with this version.
    ///
    /// New package layout (all base64 encoded for storage):
    ///   [1 byte: format version = 0x01]
    ///   [4 bytes: key version, big-endian uint32]
    ///   [1 byte: mode (0 = Random, 1 = Deterministic) — informational only, not required to decrypt]
    ///   [12 bytes: nonce]
    ///   [N bytes: ciphertext]
    ///   [16 bytes: authentication tag]
    /// </summary>
    public static class CryptoEngine
    {
        private const byte FormatVersion = 0x01;
        private const int HeaderSize = 1 + 4 + 1; // formatVersion + keyVersion + mode
        private const int NonceSize = 12;
        private const int TagSize = 16;

        public static string Encrypt(string plaintext, byte[] key, int keyVersion, EncryptionMode mode)
        {
            if (plaintext == null) return null;
            if (key == null || key.Length != 32)
                throw new ArgumentException("Key must be 256 bits (32 bytes).", nameof(key));

            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] nonce = mode == EncryptionMode.Deterministic
                ? DeriveDeterministicNonce(plaintextBytes, key)
                : RandomBytes(NonceSize);

            byte[] ciphertext = new byte[plaintextBytes.Length];
            byte[] tag = new byte[TagSize];

            using (var aesGcm = new AesGcm(key, TagSize))
            {
                aesGcm.Encrypt(nonce, plaintextBytes, ciphertext, tag);
            }

            byte[] output = new byte[HeaderSize + NonceSize + ciphertext.Length + TagSize];
            int offset = 0;

            output[offset] = FormatVersion; offset += 1;

            byte[] keyVersionBytes = BitConverter.GetBytes((uint)keyVersion);
            if (BitConverter.IsLittleEndian) Array.Reverse(keyVersionBytes);
            Buffer.BlockCopy(keyVersionBytes, 0, output, offset, 4); offset += 4;

            output[offset] = (byte)mode; offset += 1;

            Buffer.BlockCopy(nonce, 0, output, offset, NonceSize); offset += NonceSize;
            Buffer.BlockCopy(ciphertext, 0, output, offset, ciphertext.Length); offset += ciphertext.Length;
            Buffer.BlockCopy(tag, 0, output, offset, TagSize);

            return Convert.ToBase64String(output);
        }

        public static string Decrypt(string base64CipherPackage, byte[] key)
        {
            if (base64CipherPackage == null) return null;
            if (key == null || key.Length != 32)
                throw new ArgumentException("Key must be 256 bits (32 bytes).", nameof(key));

            byte[] input = Convert.FromBase64String(base64CipherPackage);
            if (input.Length < HeaderSize + NonceSize + TagSize)
                throw new CryptographicException("Ciphertext package is too short to be valid.");

            int offset = 0;
            byte formatVersion = input[offset]; offset += 1;
            if (formatVersion != FormatVersion)
                throw new CryptographicException($"Unsupported ciphertext format version: {formatVersion}. " +
                    "This is expected if the value was encrypted with an older version of CryptoEngine.");

            offset += 4; // key version — caller already used this to pick the right key before calling Decrypt
            offset += 1; // mode — informational only, not needed to decrypt

            byte[] nonce = new byte[NonceSize];
            Buffer.BlockCopy(input, offset, nonce, 0, NonceSize); offset += NonceSize;

            int cipherLen = input.Length - offset - TagSize;
            byte[] ciphertext = new byte[cipherLen];
            Buffer.BlockCopy(input, offset, ciphertext, 0, cipherLen); offset += cipherLen;

            byte[] tag = new byte[TagSize];
            Buffer.BlockCopy(input, offset, tag, 0, TagSize);

            byte[] plaintextBytes = new byte[cipherLen];
            using (var aesGcm = new AesGcm(key, TagSize))
            {
                aesGcm.Decrypt(nonce, ciphertext, tag, plaintextBytes);
            }

            return Encoding.UTF8.GetString(plaintextBytes);
        }

        /// <summary>
        /// Reads just the key version out of a ciphertext package, WITHOUT needing the key —
        /// callers use this to look up the correct key version before calling Decrypt.
        /// </summary>
        public static int ExtractKeyVersion(string base64CipherPackage)
        {
            byte[] input = Convert.FromBase64String(base64CipherPackage);
            if (input.Length < HeaderSize)
                throw new CryptographicException("Ciphertext package is too short to contain a header.");

            byte[] keyVersionBytes = new byte[4];
            Buffer.BlockCopy(input, 1, keyVersionBytes, 0, 4);
            if (BitConverter.IsLittleEndian) Array.Reverse(keyVersionBytes);
            return (int)BitConverter.ToUInt32(keyVersionBytes, 0);
        }

        public static bool LooksLikeCipherPackage(string value)
        {
            if (string.IsNullOrEmpty(value)) return false;
            try
            {
                byte[] bytes = Convert.FromBase64String(value);
                return bytes.Length >= HeaderSize + NonceSize + TagSize && bytes[0] == FormatVersion;
            }
            catch (FormatException)
            {
                return false;
            }
        }

        private static byte[] DeriveDeterministicNonce(byte[] plaintextBytes, byte[] key)
        {
            using (var hmac = new HMACSHA256(key))
            {
                byte[] hash = hmac.ComputeHash(plaintextBytes);
                byte[] nonce = new byte[NonceSize];
                Buffer.BlockCopy(hash, 0, nonce, 0, NonceSize);
                return nonce;
            }
        }

        private static byte[] RandomBytes(int length)
        {
            byte[] bytes = new byte[length];
            RandomNumberGenerator.Fill(bytes);
            return bytes;
        }

        public static byte[] GenerateKey()
        {
            byte[] key = new byte[32];
            RandomNumberGenerator.Fill(key);
            return key;
        }
    }
}
