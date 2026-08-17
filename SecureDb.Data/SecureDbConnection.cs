using System;
using System.Data.Common;
using SecureDb.Core;

namespace SecureDb.Data
{
    /// <summary>
    /// Database-agnostic wrapper. Unlike the earlier version of this file (which wrapped
    /// Microsoft.Data.SqlClient's SqlConnection directly), this wraps the generic
    /// System.Data.Common.DbConnection base class — the same base class every standard
    /// ADO.NET provider inherits from:
    ///   - Microsoft.Data.SqlClient.SqlConnection   (SQL Server)
    ///   - Npgsql.NpgsqlConnection                  (PostgreSQL)
    ///   - MySqlConnector.MySqlConnection           (MySQL)
    ///   - Oracle.ManagedDataAccess.Client.OracleConnection (Oracle)
    ///
    /// You create the real provider-specific connection yourself (so you keep full control
    /// over provider-specific connection string options) and hand it to this wrapper —
    /// everything after that point (encryption, decryption, policy lookup) is identical
    /// no matter which database it is.
    ///
    /// Example (SQL Server):
    ///   var real = new Microsoft.Data.SqlClient.SqlConnection(connStr);
    ///   var conn = new SecureDbConnection(real, policyStore, keyManager);
    ///
    /// Example (PostgreSQL, if you add the Npgsql package later):
    ///   var real = new Npgsql.NpgsqlConnection(connStr);
    ///   var conn = new SecureDbConnection(real, policyStore, keyManager);
    /// Same SecureDbConnection class, same policy file, same encryption code — only the
    /// first line changes.
    /// </summary>
    public class SecureDbConnection : IDisposable
    {
        private readonly DbConnection _inner;
        private readonly PolicyStore _policyStore;
        private readonly KeyManager _keyManager;

        public SecureDbConnection(DbConnection innerConnection, PolicyStore policyStore, KeyManager keyManager)
        {
            _inner = innerConnection ?? throw new ArgumentNullException(nameof(innerConnection));
            _policyStore = policyStore;
            _keyManager = keyManager;
        }

        public void Open() => _inner.Open();

        public void Close() => _inner.Close();

        public System.Data.ConnectionState State => _inner.State;

        public SecureDbCommand CreateCommand(string commandText = null, string tableName = null)
        {
            DbCommand dbCommand = _inner.CreateCommand();
            if (commandText != null)
                dbCommand.CommandText = commandText;

            return new SecureDbCommand(dbCommand, _policyStore, _keyManager, tableName);
        }

        public DbTransaction BeginTransaction() => _inner.BeginTransaction();

        /// <summary>Escape hatch if you ever need the real provider connection directly.</summary>
        public DbConnection Underlying => _inner;

        public void Dispose()
        {
            _inner?.Dispose();
        }
    }
}
