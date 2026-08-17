using System;
using System.Collections.Generic;
using System.Data.Common;
using SecureDb.Core;

namespace SecureDb.Data
{
    /// <summary>
    /// Database-agnostic reader wrapper. Wraps System.Data.Common.DbDataReader instead of
    /// a provider-specific reader type — works identically whether the result set came from
    /// SQL Server, PostgreSQL, MySQL, or Oracle.
    /// </summary>
    public class SecureDataReader : IDisposable
    {
        private readonly DbDataReader _inner;
        private readonly PolicyStore _policyStore;
        private readonly KeyManager _keyManager;
        private readonly string _tableName;
        private readonly Dictionary<int, ColumnPolicy> _ordinalPolicyCache = new Dictionary<int, ColumnPolicy>();
        private bool _cacheBuilt;

        internal SecureDataReader(DbDataReader inner, PolicyStore policyStore, KeyManager keyManager, string tableName = null)
        {
            _inner = inner;
            _policyStore = policyStore;
            _keyManager = keyManager;
            _tableName = tableName;
        }

        public bool Read() => _inner.Read();

        public int FieldCount => _inner.FieldCount;

        public string GetName(int ordinal) => _inner.GetName(ordinal);

        public bool IsDBNull(int ordinal) => _inner.IsDBNull(ordinal);

        public object this[string columnName]
        {
            get
            {
                int ordinal = _inner.GetOrdinal(columnName);
                return GetValue(ordinal);
            }
        }

        public string GetString(int ordinal)
        {
            object value = GetValue(ordinal);
            return value == null || value == DBNull.Value ? null : value.ToString();
        }

        public object GetValue(int ordinal)
        {
            if (_inner.IsDBNull(ordinal))
                return DBNull.Value;

            EnsureCacheBuilt();

            if (_ordinalPolicyCache.TryGetValue(ordinal, out ColumnPolicy policy))
            {
                string ciphertext = _inner.GetString(ordinal);
                try
                {
                    int keyVersion = CryptoEngine.ExtractKeyVersion(ciphertext);
                    byte[] dek = _keyManager.GetKeyByVersion(policy.KeyId, keyVersion);
                    return CryptoEngine.Decrypt(ciphertext, dek);
                }
                catch (FormatException)
                {
                    // Not valid base64 at all — wasn't ciphertext to begin with.
                    return ciphertext;
                }
                catch (System.Security.Cryptography.CryptographicException)
                {
                    // Valid base64 but not a recognizable ciphertext package — e.g. a row
                    // encrypted under the OLD (pre-versioning) format. Surface the raw value
                    // rather than crashing the whole read.
                    return ciphertext;
                }
            }

            return _inner.GetValue(ordinal);
        }

        private void EnsureCacheBuilt()
        {
            if (_cacheBuilt) return;

            for (int i = 0; i < _inner.FieldCount; i++)
            {
                string columnName = _inner.GetName(i);
                if (_policyStore.TryGetPolicy(columnName, _tableName, out ColumnPolicy policy) && policy.Enabled)
                {
                    _ordinalPolicyCache[i] = policy;
                }
            }
            _cacheBuilt = true;
        }

        public void Dispose()
        {
            _inner?.Dispose();
        }
    }
}
