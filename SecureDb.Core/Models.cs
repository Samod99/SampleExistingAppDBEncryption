using System;

namespace SecureDb.Core
{
    /// <summary>
    /// A protection rule. TableName is optional: leave it null/empty for a rule that applies
    /// to any table with a matching column name (the original behavior). Set it to make the
    /// rule apply ONLY to that specific table — needed once two different tables have a
    /// same-named column that should be treated differently (e.g. Customer.Email protected,
    /// Vendor.Email not).
    /// </summary>
    public class ColumnPolicy
    {
        public string TableName { get; set; }
        public string ColumnName { get; set; }
        public string KeyId { get; set; }
        public EncryptionMode Mode { get; set; }
        public bool Enabled { get; set; } = true;
    }

    /// <summary>A wrapped (KEK-encrypted) Data Encryption Key, now with an explicit version
    /// number so key rotation and versioned ciphertext can work correctly together.</summary>
    public class WrappedKeyEntry
    {
        public string KeyId { get; set; }
        public int KeyVersion { get; set; }
        public string WrappedKeyBase64 { get; set; }
        public DateTime CreatedUtc { get; set; }
    }

    /// <summary>Raw schema metadata for one column, as discovered from INFORMATION_SCHEMA.
    /// Lives in Core (not Profiler) because SchemaDiscovery is shared infrastructure —
    /// SecureDb.MigrationTool needs it too, to auto-detect a safe row identifier.</summary>
    public class ColumnInfo
    {
        public string Schema { get; set; }
        public string Table { get; set; }
        public string Column { get; set; }
        public string DataType { get; set; }
        public int? MaxLength { get; set; }
        public bool IsNullable { get; set; }
        public bool IsPrimaryKey { get; set; }
        public bool IsForeignKey { get; set; }
    }
}
