using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using SecureDb.Core;

namespace SecureDb.Data
{
    /// <summary>
    /// Database-agnostic command wrapper. Wraps System.Data.Common.DbCommand instead of a
    /// provider-specific command type, so this same class works whether the underlying
    /// connection is SQL Server, PostgreSQL, MySQL, or Oracle.
    ///
    /// Optionally table-aware: pass a tableName to conn.CreateCommand(sql, tableName) and
    /// policy lookups will prefer a rule specific to that table over a column-name-only
    /// rule — needed once two different tables have a same-named column that should be
    /// treated differently (e.g. Customer.Email protected, Vendor.Email not). Omitting
    /// tableName keeps the original column-name-only behavior, unchanged.
    ///
    ///     var cmd = conn.CreateCommand(
    ///         "INSERT INTO Customer (Name, SSN) VALUES (@Name, @SSN)", tableName: "Customer");
    ///     cmd.AddParameter("@Name", "Jane Doe");
    ///     cmd.AddParameter("@SSN", "123-45-6789");   // auto-encrypted, same as before
    ///     cmd.ExecuteNonQuery();
    /// </summary>
    public class SecureDbCommand : IDisposable
    {
        private readonly DbCommand _inner;
        private readonly PolicyStore _policyStore;
        private readonly KeyManager _keyManager;
        private readonly string _tableName;
        private readonly Dictionary<string, string> _explicitParamToColumn =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        internal SecureDbCommand(DbCommand inner, PolicyStore policyStore, KeyManager keyManager, string tableName = null)
        {
            _inner = inner;
            _policyStore = policyStore;
            _keyManager = keyManager;
            _tableName = tableName;
        }

        public string CommandText
        {
            get => _inner.CommandText;
            set => _inner.CommandText = value;
        }

        public DbParameterCollection Parameters => _inner.Parameters;

        public DbTransaction Transaction
        {
            get => _inner.Transaction;
            set => _inner.Transaction = value;
        }

        /// <summary>Provider-agnostic replacement for SqlCommand's "AddWithValue".</summary>
        public DbParameter AddParameter(string name, object value)
        {
            DbParameter param = _inner.CreateParameter();
            param.ParameterName = name;
            param.Value = value ?? DBNull.Value;
            _inner.Parameters.Add(param);
            return param;
        }

        /// <summary>Explicitly map a parameter to a protected column when the names don't already match.</summary>
        public void ProtectParameter(string parameterName, string columnName)
        {
            _explicitParamToColumn[parameterName] = columnName;
        }

        public int ExecuteNonQuery()
        {
            EncryptOutboundParameters();
            return _inner.ExecuteNonQuery();
        }

        public object ExecuteScalar()
        {
            EncryptOutboundParameters();
            return _inner.ExecuteScalar();
        }

        public SecureDataReader ExecuteReader()
        {
            EncryptOutboundParameters();
            DbDataReader reader = _inner.ExecuteReader();
            return new SecureDataReader(reader, _policyStore, _keyManager, _tableName);
        }

        private void EncryptOutboundParameters()
        {
            foreach (DbParameter param in _inner.Parameters)
            {
                if (param.Value == null || param.Value == DBNull.Value)
                    continue;

                string columnName = ResolveColumnName(param.ParameterName);
                if (columnName == null)
                    continue;

                if (!_policyStore.TryGetPolicy(columnName, _tableName, out ColumnPolicy policy) || !policy.Enabled)
                    continue;

                string plaintext = param.Value.ToString();

                if (CryptoEngine.LooksLikeCipherPackage(plaintext))
                    continue;

                byte[] dek = _keyManager.GetCurrentKey(policy.KeyId, out int keyVersion);
                string ciphertext = CryptoEngine.Encrypt(plaintext, dek, keyVersion, policy.Mode);

                param.Value = ciphertext;
                param.DbType = DbType.String;
                param.Size = -1;
            }
        }

        private string ResolveColumnName(string parameterName)
        {
            if (_explicitParamToColumn.TryGetValue(parameterName, out string mapped))
                return mapped;

            // Default convention: @ColumnName / :ColumnName -> ColumnName
            // (different providers use different parameter prefixes: SQL Server uses "@",
            // Oracle/Postgres often use ":" — strip either.)
            return parameterName.TrimStart('@', ':');
        }

        public void Dispose()
        {
            _inner?.Dispose();
        }
    }
}
