using System;
using System.Collections.Generic;
using System.Data.Common;

namespace SecureDb.Core
{
    /// <summary>
    /// Discovers table/column metadata AND key information (primary + foreign) using
    /// INFORMATION_SCHEMA — a standard set of views supported (with only minor variation)
    /// by SQL Server, PostgreSQL, and MySQL alike. This is the "Database Identification"
    /// step: a clear, structural picture of what's actually in the database, produced
    /// BEFORE any sensitivity classification or encryption decision is made.
    ///
    /// Knowing primary/foreign keys matters for more than documentation: encrypting either
    /// one breaks joins and referential integrity outright, so classification hard-excludes
    /// any column flagged here — see ColumnClassifier.
    /// </summary>
    public static class SchemaDiscovery
    {
        private static readonly string[] SystemSchemas =
        {
            "sys", "information_schema", "pg_catalog", "guest"
        };

        public static List<ColumnInfo> DiscoverColumns(DbConnection connection)
        {
            var results = new List<ColumnInfo>();
            var primaryKeys = DiscoverKeyColumns(connection, "PRIMARY KEY");
            var foreignKeys = DiscoverKeyColumns(connection, "FOREIGN KEY");

            using (var cmd = connection.CreateCommand())
            {
                cmd.CommandText =
                    "SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE, " +
                    "       CHARACTER_MAXIMUM_LENGTH, IS_NULLABLE " +
                    "FROM INFORMATION_SCHEMA.COLUMNS " +
                    "ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION";

                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        string schema = reader["TABLE_SCHEMA"]?.ToString() ?? "";
                        if (IsSystemSchema(schema))
                            continue;

                        string table = reader["TABLE_NAME"].ToString();
                        string column = reader["COLUMN_NAME"].ToString();
                        object maxLenRaw = reader["CHARACTER_MAXIMUM_LENGTH"];
                        var key = (schema, table, column);

                        results.Add(new ColumnInfo
                        {
                            Schema = schema,
                            Table = table,
                            Column = column,
                            DataType = reader["DATA_TYPE"].ToString(),
                            MaxLength = (maxLenRaw == DBNull.Value || maxLenRaw == null)
                                ? (int?)null
                                : Convert.ToInt32(maxLenRaw),
                            IsNullable = string.Equals(
                                reader["IS_NULLABLE"]?.ToString(), "YES", StringComparison.OrdinalIgnoreCase),
                            IsPrimaryKey = primaryKeys.Contains(key),
                            IsForeignKey = foreignKeys.Contains(key)
                        });
                    }
                }
            }

            return results;
        }

        /// <summary>
        /// Finds every (schema, table, column) participating in a constraint of the given
        /// type ("PRIMARY KEY" or "FOREIGN KEY"), using the standard TABLE_CONSTRAINTS +
        /// KEY_COLUMN_USAGE join — supported across SQL Server, PostgreSQL, and MySQL.
        /// </summary>
        private static HashSet<(string Schema, string Table, string Column)> DiscoverKeyColumns(
            DbConnection connection, string constraintType)
        {
            var result = new HashSet<(string, string, string)>();

            try
            {
                using (var cmd = connection.CreateCommand())
                {
                    cmd.CommandText =
                        "SELECT kcu.TABLE_SCHEMA, kcu.TABLE_NAME, kcu.COLUMN_NAME " +
                        "FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc " +
                        "JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE kcu " +
                        "  ON tc.CONSTRAINT_NAME = kcu.CONSTRAINT_NAME " +
                        " AND tc.TABLE_SCHEMA = kcu.TABLE_SCHEMA " +
                        $"WHERE tc.CONSTRAINT_TYPE = '{constraintType}'";

                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            result.Add((
                                reader["TABLE_SCHEMA"]?.ToString() ?? "",
                                reader["TABLE_NAME"]?.ToString() ?? "",
                                reader["COLUMN_NAME"]?.ToString() ?? ""));
                        }
                    }
                }
            }
            catch
            {
                // If this fails for any reason (permissions, an engine-specific quirk),
                // fall back to "none known" rather than aborting discovery entirely — key
                // info is safety-critical when found, but its absence shouldn't block
                // everything else from working.
            }

            return result;
        }

        private static bool IsSystemSchema(string schema)
        {
            foreach (var s in SystemSchemas)
            {
                if (s.Equals(schema, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }
    }
}
