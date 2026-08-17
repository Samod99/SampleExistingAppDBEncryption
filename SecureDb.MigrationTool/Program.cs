using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Linq;
using Microsoft.Data.SqlClient;
using SecureDb.Core;

namespace SecureDb.MigrationTool
{
    /// <summary>
    /// Encrypts already-existing plaintext values for EVERY enabled policy in policy.json,
    /// across however many tables it covers — this is the "any tables included" piece:
    /// one run handles your whole approved policy set, not one hardcoded table/column.
    ///
    /// For each policy, the table's primary key is auto-detected via SchemaDiscovery (shared
    /// with SecureDb.Profiler) rather than typed in by hand. A policy for a table with no
    /// discoverable primary key is skipped with a clear message, not silently guessed at.
    ///
    /// Deliberately does NOT use SecureDbConnection/SecureDbCommand — reads/writes raw
    /// ciphertext directly rather than through the transparent wrapper.
    ///
    /// SAFE TO RE-RUN: every row is checked with CryptoEngine.LooksLikeCipherPackage before
    /// being touched.
    ///
    /// ⚠️ SCALE WARNING: loads all rows per table into memory. Fine for testing; a
    /// production version needs proper batching for large tables.
    ///
    /// ⚠️ NOT YET RUN against a real database on my end. Test against a COPY of your data
    /// first, and take a real backup before running this against anything that matters.
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            string connectionString =
                @"Server=localhost\SQLEXPRESS;Database=CompanyDB;Integrated Security=true;TrustServerCertificate=true;";
            //string policyFilePath = @"..\..\..\..\policy.json";
            string policyFilePath = @"..\..\..\..\SampleExistingApp.WinForms\policy.json";
            string keyStoreDirectory = @"C:\ProgramData\SampleExistingApp";

            var policyStore = new PolicyStore(policyFilePath);
            var keyManager = new KeyManager(keyStoreDirectory);

            List<ColumnPolicy> enabledPolicies = policyStore.AllPolicies.Where(p => p.Enabled).ToList();
            if (enabledPolicies.Count == 0)
            {
                Console.WriteLine("No enabled policies found in policy.json. Nothing to migrate.");
                return;
            }

            Console.WriteLine("== SecureDb Migration Tool ==");
            Console.WriteLine($"Found {enabledPolicies.Count} enabled polic{(enabledPolicies.Count == 1 ? "y" : "ies")} to process.");
            Console.WriteLine();

            using (DbConnection connection = new SqlConnection(connectionString))
            {
                connection.Open();

                // Database Identification, once, up front — reused for every policy below,
                // rather than re-querying the schema per table.
                List<ColumnInfo> allColumns = SchemaDiscovery.DiscoverColumns(connection);

                int totalMigrated = 0, totalAlreadyDone = 0, totalFailed = 0, totalSkippedTables = 0;

                foreach (var policy in enabledPolicies)
                {
                    if (string.IsNullOrWhiteSpace(policy.TableName))
                    {
                        Console.WriteLine($"Skipping '{policy.ColumnName}': policy has no TableName set, so this " +
                                           "tool doesn't know which table to migrate. Add TableName to this policy " +
                                           "entry (SecureDb.Profiler now writes this automatically for new policies).");
                        totalSkippedTables++;
                        continue;
                    }

                    string idColumnName = AutoDetectIdColumn(allColumns, policy.TableName);
                    if (idColumnName == null)
                    {
                        Console.WriteLine($"Skipping {policy.TableName}.{policy.ColumnName}: no primary key " +
                                           "found for this table, so there's no safe way to target individual " +
                                           "rows for UPDATE. This needs a manual, table-specific approach.");
                        totalSkippedTables++;
                        continue;
                    }

                    Console.WriteLine($"-- {policy.TableName}.{policy.ColumnName} (row id: {idColumnName}) --");

                    var (migrated, alreadyDone, failed) = MigrateColumn(
                        connection, policy, idColumnName, keyManager);

                    totalMigrated += migrated;
                    totalAlreadyDone += alreadyDone;
                    totalFailed += failed;
                    Console.WriteLine();
                }

                Console.WriteLine("== Overall Summary ==");
                Console.WriteLine($"  Migrated       : {totalMigrated}");
                Console.WriteLine($"  Already done   : {totalAlreadyDone}");
                Console.WriteLine($"  Failed         : {totalFailed}");
                Console.WriteLine($"  Tables skipped : {totalSkippedTables}");
            }

            Console.WriteLine();
            Console.WriteLine("Done. Press any key to exit.");
            Console.ReadKey();
        }

        private static (int migrated, int alreadyDone, int failed) MigrateColumn(
            DbConnection connection, ColumnPolicy policy, string idColumnName, KeyManager keyManager)
        {
            var rows = ReadAllRows(connection, policy.TableName, idColumnName, policy.ColumnName);
            Console.WriteLine($"   Read {rows.Count} row(s).");

            int migrated = 0, alreadyDone = 0, failed = 0;

            foreach (var (id, currentValue) in rows)
            {
                try
                {
                    if (currentValue == null || CryptoEngine.LooksLikeCipherPackage(currentValue))
                    {
                        alreadyDone++;
                        continue;
                    }

                    byte[] dek = keyManager.GetCurrentKey(policy.KeyId, out int keyVersion);
                    string ciphertext = CryptoEngine.Encrypt(currentValue, dek, keyVersion, policy.Mode);

                    UpdateRow(connection, policy.TableName, idColumnName, policy.ColumnName, id, ciphertext);
                    migrated++;
                }
                catch (Exception ex)
                {
                    failed++;
                    Console.WriteLine($"   FAILED on id='{id}': {ex.Message}");
                }
            }

            Console.WriteLine($"   Migrated={migrated}, AlreadyDone={alreadyDone}, Failed={failed}");
            return (migrated, alreadyDone, failed);
        }

        private static string AutoDetectIdColumn(List<ColumnInfo> allColumns, string tableName)
        {
            var primaryKeyColumns = allColumns
                .Where(c => string.Equals(c.Table, tableName, StringComparison.OrdinalIgnoreCase) && c.IsPrimaryKey)
                .Select(c => c.Column)
                .ToList();

            if (primaryKeyColumns.Count == 0)
                return null;

            if (primaryKeyColumns.Count > 1)
                Console.WriteLine($"   Note: '{tableName}' has a composite primary key ({string.Join(", ", primaryKeyColumns)}); using the first column only.");

            return primaryKeyColumns[0];
        }

        private static List<(string Id, string Value)> ReadAllRows(
            DbConnection connection, string table, string idColumn, string targetColumn)
        {
            var results = new List<(string, string)>();
            using (var cmd = connection.CreateCommand())
            {
                cmd.CommandText = $"SELECT {idColumn}, {targetColumn} FROM {table}";
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        string id = reader.IsDBNull(0) ? null : reader.GetValue(0).ToString();
                        string value = reader.IsDBNull(1) ? null : reader.GetValue(1).ToString();
                        results.Add((id, value));
                    }
                }
            }
            return results;
        }

        private static void UpdateRow(
            DbConnection connection, string table, string idColumn, string targetColumn,
            string id, string newValue)
        {
            using (var cmd = connection.CreateCommand())
            {
                cmd.CommandText = $"UPDATE {table} SET {targetColumn} = @newValue WHERE {idColumn} = @id";

                var valueParam = cmd.CreateParameter();
                valueParam.ParameterName = "@newValue";
                valueParam.Value = (object)newValue ?? DBNull.Value;
                cmd.Parameters.Add(valueParam);

                var idParam = cmd.CreateParameter();
                idParam.ParameterName = "@id";
                idParam.Value = (object)id ?? DBNull.Value;
                cmd.Parameters.Add(idParam);

                cmd.ExecuteNonQuery();
            }
        }
    }
}
