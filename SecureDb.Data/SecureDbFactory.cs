using System;
using System.Data.Common;
using SecureDb.Core;

namespace SecureDb.Data
{
    /// <summary>
    /// One-call setup for a new consuming application. Without this, wiring up SecureDb
    /// means separately constructing KeyManager, PolicyStore, and SecureDbConnection —
    /// three steps that always go together in practice. This collapses them into one.
    ///
    /// Example (in a brand new WinForms app that has never seen SecureDb before):
    ///
    ///     var realConnection = new Microsoft.Data.SqlClient.SqlConnection(myConnectionString);
    ///     var conn = SecureDbFactory.Create(
    ///         realConnection,
    ///         keyStoreDirectory: @"C:\ProgramData\MyApp\SecureDb",
    ///         policyFilePath: Path.Combine(AppContext.BaseDirectory, "policy.json"));
    ///     conn.Open();
    ///     // use conn.CreateCommand(...) exactly as shown throughout this project
    /// </summary>
    public static class SecureDbFactory
    {
        public static SecureDbConnection Create(DbConnection realConnection, string keyStoreDirectory, string policyFilePath)
        {
            if (realConnection == null) throw new ArgumentNullException(nameof(realConnection));
            if (string.IsNullOrWhiteSpace(keyStoreDirectory)) throw new ArgumentException("Key store directory is required.", nameof(keyStoreDirectory));
            if (string.IsNullOrWhiteSpace(policyFilePath)) throw new ArgumentException("Policy file path is required.", nameof(policyFilePath));

            var keyManager = new KeyManager(keyStoreDirectory);
            var policyStore = new PolicyStore(policyFilePath);
            return new SecureDbConnection(realConnection, policyStore, keyManager);
        }
    }
}
