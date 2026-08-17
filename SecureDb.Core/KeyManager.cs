using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;

namespace SecureDb.Core
{
    /// <summary>
    /// Local, single-machine stand-in for a real Key & Policy Service. See earlier notes:
    /// move this to Azure Key Vault/AWS KMS/HashiCorp Vault before any real use.
    ///
    /// Now version-aware: each keyId can have multiple versions (from rotation), and callers
    /// can fetch either "the current version" (for new encryption) or "a specific version"
    /// (for decrypting an older row that was encrypted before the last rotation).
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class KeyManager
    {
        private readonly string _keystorePath;
        private readonly string _masterKeyPath;
        private readonly ConcurrentDictionary<string, byte[]> _unwrappedKeyCache = new ConcurrentDictionary<string, byte[]>();
        private byte[] _masterKey;

        public KeyManager(string storageDirectory)
        {
            Directory.CreateDirectory(storageDirectory);
            _keystorePath = Path.Combine(storageDirectory, "keystore.json");
            _masterKeyPath = Path.Combine(storageDirectory, "master.key");
            EnsureMasterKey();
        }

        /// <summary>Gets the current (latest) key version for a keyId, creating version 1 if
        /// the keyId has never been used before. Use this when ENCRYPTING new values.</summary>
        public byte[] GetCurrentKey(string keyId, out int version)
        {
            var store = LoadKeystore();
            var entries = store.Where(e => e.KeyId == keyId).OrderByDescending(e => e.KeyVersion).ToList();

            if (entries.Count == 0)
            {
                byte[] newDek = CryptoEngine.GenerateKey();
                var entry = new WrappedKeyEntry
                {
                    KeyId = keyId,
                    KeyVersion = 1,
                    WrappedKeyBase64 = WrapKey(newDek),
                    CreatedUtc = DateTime.UtcNow
                };
                AppendKeystoreEntry(entry);
                version = 1;
                CacheKey(keyId, 1, newDek);
                return newDek;
            }

            var latest = entries[0];
            version = latest.KeyVersion;
            return GetOrUnwrapCached(keyId, latest.KeyVersion, latest.WrappedKeyBase64);
        }

        /// <summary>Gets a SPECIFIC key version — use this when DECRYPTING an existing value,
        /// since the value's ciphertext header tells you exactly which version it needs.</summary>
        public byte[] GetKeyByVersion(string keyId, int version)
        {
            string cacheKey = CacheKeyFor(keyId, version);
            if (_unwrappedKeyCache.TryGetValue(cacheKey, out byte[] cached))
                return cached;

            var store = LoadKeystore();
            var entry = store.FirstOrDefault(e => e.KeyId == keyId && e.KeyVersion == version);
            if (entry == null)
                throw new InvalidOperationException(
                    $"No key found for keyId='{keyId}', version={version}. " +
                    "This usually means the keystore.json file was deleted/changed after this data was encrypted.");

            byte[] dek = UnwrapKey(entry.WrappedKeyBase64);
            CacheKey(keyId, version, dek);
            return dek;
        }

        /// <summary>Rotates a keyId to a new version. Existing rows keep decrypting correctly
        /// via GetKeyByVersion using their embedded version number; new writes will pick up
        /// the new version through GetCurrentKey. There is deliberately no automatic
        /// re-encryption of old rows here — see the README for the lazy re-encryption pattern.</summary>
        public byte[] RotateKey(string keyId)
        {
            var store = LoadKeystore();
            int nextVersion = store.Where(e => e.KeyId == keyId).Select(e => e.KeyVersion).DefaultIfEmpty(0).Max() + 1;

            byte[] newDek = CryptoEngine.GenerateKey();
            AppendKeystoreEntry(new WrappedKeyEntry
            {
                KeyId = keyId,
                KeyVersion = nextVersion,
                WrappedKeyBase64 = WrapKey(newDek),
                CreatedUtc = DateTime.UtcNow
            });
            CacheKey(keyId, nextVersion, newDek);
            return newDek;
        }

        private byte[] GetOrUnwrapCached(string keyId, int version, string wrappedBase64)
        {
            string cacheKey = CacheKeyFor(keyId, version);
            if (_unwrappedKeyCache.TryGetValue(cacheKey, out byte[] cached))
                return cached;

            byte[] dek = UnwrapKey(wrappedBase64);
            CacheKey(keyId, version, dek);
            return dek;
        }

        private void CacheKey(string keyId, int version, byte[] dek)
        {
            _unwrappedKeyCache[CacheKeyFor(keyId, version)] = dek;
        }

        private static string CacheKeyFor(string keyId, int version) => $"{keyId}::v{version}";

        private void EnsureMasterKey()
        {
            if (File.Exists(_masterKeyPath))
            {
                byte[] protectedBytes = File.ReadAllBytes(_masterKeyPath);
                _masterKey = ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.LocalMachine);
            }
            else
            {
                _masterKey = CryptoEngine.GenerateKey();
                byte[] protectedBytes = ProtectedData.Protect(_masterKey, null, DataProtectionScope.LocalMachine);
                File.WriteAllBytes(_masterKeyPath, protectedBytes);
            }
        }

        private string WrapKey(byte[] dek)
        {
            string dekBase64 = Convert.ToBase64String(dek);
            // Wrapping itself always uses version "0"/Random mode — this is about protecting
            // the DEK at rest, not about the DEK's own version number as used by callers.
            return CryptoEngine.Encrypt(dekBase64, _masterKey, keyVersion: 0, EncryptionMode.Random);
        }

        private byte[] UnwrapKey(string wrappedBase64)
        {
            try
            {
                string dekBase64 = CryptoEngine.Decrypt(wrappedBase64, _masterKey);
                return Convert.FromBase64String(dekBase64);
            }
            catch (CryptographicException ex)
            {
                throw new InvalidOperationException(
                    "Failed to unwrap a stored key. This usually means keystore.json on disk " +
                    "was created by an older, incompatible version of CryptoEngine (e.g. before " +
                    "the ciphertext-versioning change). Fix: delete the keystore folder " +
                    "(the directory passed into KeyManager's constructor, e.g. " +
                    "C:\\ProgramData\\SecureDbPrototype) and run again so it regenerates cleanly. " +
                    "This is safe for a prototype with no real data at stake yet.",
                    ex);
            }
        }

        private WrappedKeyEntry[] LoadKeystore()
        {
            if (!File.Exists(_keystorePath))
                return Array.Empty<WrappedKeyEntry>();

            string json = File.ReadAllText(_keystorePath);
            if (string.IsNullOrWhiteSpace(json))
                return Array.Empty<WrappedKeyEntry>();

            return JsonSerializer.Deserialize<WrappedKeyEntry[]>(json) ?? Array.Empty<WrappedKeyEntry>();
        }

        private void AppendKeystoreEntry(WrappedKeyEntry entry)
        {
            var current = LoadKeystore();
            var updated = new WrappedKeyEntry[current.Length + 1];
            Array.Copy(current, updated, current.Length);
            updated[current.Length] = entry;

            string json = JsonSerializer.Serialize(updated, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_keystorePath, json);
        }
    }
}
