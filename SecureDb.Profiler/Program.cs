using System;
using System.Collections.Generic;
using System.Data.Common;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.SqlClient;
using SecureDb.Core;

namespace SecureDb.Profiler
{
    /// <summary>
    /// Phase 0 of the pipeline: Database Identification (schema + keys) → Classification →
    /// (human approval) → Policy. This never encrypts anything itself.
    ///
    /// Two files come out of a run:
    ///   - database-identity-report.json — a plain structural map of every table/column
    ///     found (including which columns are primary keys), independent of sensitivity.
    ///     This is the "clearly identify the database" artifact — useful even if you
    ///     approve zero columns for encryption, since it's just documentation of what's
    ///     actually in the database.
    ///   - policy.generated.json — the sensitivity recommendations you explicitly approve,
    ///     now written WITH the table name attached to each rule, so two different tables
    ///     with a same-named column (e.g. Customer.Email vs Vendor.Email) can be governed
    ///     independently instead of being treated as the same thing.
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            string connectionString =
                @"Server=localhost\SQLEXPRESS;Database=CompanyDB;Integrated Security=true;TrustServerCertificate=true;";

            Console.WriteLine("== SecureDb Profiler ==");
            Console.WriteLine("Step 1: identify the database's actual structure.");
            Console.WriteLine("Step 2: suggest which columns look sensitive.");
            Console.WriteLine("Neither step encrypts anything — recommendations only.");
            Console.WriteLine();

            using (DbConnection connection = new SqlConnection(connectionString))
            {
                connection.Open();

                List<ColumnInfo> columns = SchemaDiscovery.DiscoverColumns(connection);
                Console.WriteLine($"Identified {columns.Count} column(s) across the database.");

                int pkCount = columns.Count(c => c.IsPrimaryKey);
                Console.WriteLine($"  ({pkCount} of them are primary key columns.)");
                Console.WriteLine();

                WriteDatabaseIdentityReport(columns);

                var classifier = new ColumnClassifier(connection);
                List<ClassificationResult> allResults = classifier.ClassifyAll(columns)
                    .OrderByDescending(r => r.Confidence)
                    .ToList();

                if (allResults.Count == 0)
                {
                    Console.WriteLine("No columns matched any sensitive-data pattern. Nothing further to report.");
                    return;
                }

                // Key-column warnings are informational only — never selectable for
                // encryption, since that would break joins/referential integrity. Only
                // "normal" results are numbered and offered for approval.
                List<ClassificationResult> keyWarnings = allResults.Where(r => r.IsKeyColumnWarning).ToList();
                List<ClassificationResult> results = allResults.Where(r => !r.IsKeyColumnWarning).ToList();

                PrintKeyColumnWarnings(keyWarnings);

                if (results.Count == 0)
                {
                    Console.WriteLine("No further columns matched any sensitive-data pattern.");
                    return;
                }

                PrintReport(results);

                List<ClassificationResult> approved = PromptForApproval(results);
                if (approved.Count == 0)
                {
                    Console.WriteLine("No columns approved. No policy written.");
                    return;
                }

                WritePolicyFile(approved);
            }

            Console.WriteLine();
            Console.WriteLine("Done. Press any key to exit.");
            Console.ReadKey();
        }

        private static void WriteDatabaseIdentityReport(List<ColumnInfo> columns)
        {
            var byTable = columns
                .GroupBy(c => new { c.Schema, c.Table })
                .Select(g => new
                {
                    schema = g.Key.Schema,
                    table = g.Key.Table,
                    primaryKey = g.Where(c => c.IsPrimaryKey).Select(c => c.Column).ToList(),
                    foreignKeys = g.Where(c => c.IsForeignKey).Select(c => c.Column).ToList(),
                    columns = g.Select(c => new
                    {
                        name = c.Column,
                        dataType = c.DataType,
                        maxLength = c.MaxLength,
                        nullable = c.IsNullable,
                        isPrimaryKey = c.IsPrimaryKey,
                        isForeignKey = c.IsForeignKey
                    }).ToList()
                })
                .OrderBy(t => t.schema).ThenBy(t => t.table)
                .ToList();

            string outputPath = Path.Combine(AppContext.BaseDirectory, "database-identity-report.json");
            File.WriteAllText(outputPath, JsonSerializer.Serialize(byTable, new JsonSerializerOptions { WriteIndented = true }));

            Console.WriteLine($"Wrote a full structural map to: {outputPath}");
            Console.WriteLine("(Every table, every column, types, and primary keys — independent of sensitivity.)");
            Console.WriteLine();
        }

        private static void PrintKeyColumnWarnings(List<ClassificationResult> keyWarnings)
        {
            if (keyWarnings.Count == 0) return;

            Console.WriteLine("\u26A0 Key columns that LOOK sensitive by name — NOT offered for encryption:");
            Console.WriteLine("  (Encrypting a primary/foreign key breaks joins and referential integrity.");
            Console.WriteLine("   If this needs protecting, use a surrogate key + tokenization instead —");
            Console.WriteLine("   not something this tool can safely do automatically.)");
            foreach (var kw in keyWarnings)
            {
                Console.WriteLine($"    - {kw.Table}.{kw.Column} ({kw.Category})");
            }
            Console.WriteLine();
        }

        private static void PrintReport(List<ClassificationResult> results)
        {
            Console.WriteLine("Recommended columns to protect:");
            Console.WriteLine();
            Console.WriteLine(string.Format("{0,-4}{1,-16}{2,-16}{3,-14}{4,-16}{5,-15}",
                "#", "Table", "Column", "Category", "Confidence", "Suggested Mode"));
            Console.WriteLine(new string('-', 82));

            for (int i = 0; i < results.Count; i++)
            {
                var r = results[i];
                string confidenceLabel = ConfidenceLabel(r.Confidence);
                string confidenceText = $"{confidenceLabel} ({r.Confidence:P0})";

                Console.WriteLine(string.Format("{0,-4}{1,-16}{2,-16}{3,-14}{4,-16}{5,-15}",
                    i + 1, r.Table, r.Column, r.Category, confidenceText, r.SuggestedMode));

                if (r.IsPasswordLike)
                {
                    Console.WriteLine("     \u26A0 This looks like a password column. Passwords should normally be");
                    Console.WriteLine("       HASHED (bcrypt/Argon2/PBKDF2), not encrypted — hashing can't be");
                    Console.WriteLine("       reversed even by you; encryption deliberately can. Only approve");
                    Console.WriteLine("       this if you specifically need the plaintext back for some reason.");
                }
            }
            Console.WriteLine();
        }

        private static string ConfidenceLabel(double confidence)
        {
            if (confidence >= 0.8) return "HIGH";
            if (confidence >= 0.5) return "MEDIUM";
            return "LOW";
        }

        private static List<ClassificationResult> PromptForApproval(List<ClassificationResult> results)
        {
            Console.Write("Enter the numbers to approve for encryption (comma-separated), 'all', or 'none': ");
            string input = (Console.ReadLine() ?? "none").Trim();

            if (string.Equals(input, "all", StringComparison.OrdinalIgnoreCase))
                return results;

            if (string.Equals(input, "none", StringComparison.OrdinalIgnoreCase) || input.Length == 0)
                return new List<ClassificationResult>();

            var approved = new List<ClassificationResult>();
            string[] parts = input.Split(',');
            foreach (var part in parts)
            {
                if (int.TryParse(part.Trim(), out int index) && index >= 1 && index <= results.Count)
                    approved.Add(results[index - 1]);
            }
            return approved;
        }

        private static void WritePolicyFile(List<ClassificationResult> approved)
        {
            // TableName is now included on every generated policy — this is what lets
            // Customer.Email and Vendor.Email be governed independently, instead of the
            // profiler accidentally conflating same-named columns across different tables.
            List<ColumnPolicy> policies = approved.Select(r => new ColumnPolicy
            {
                TableName = r.Table,
                ColumnName = r.Column,
                KeyId = $"{r.Table}-{r.Column}-v1".ToLowerInvariant(),
                Mode = r.SuggestedMode,
                Enabled = true
            }).ToList();

            string outputPath = Path.Combine(AppContext.BaseDirectory, "policy.generated.json");
            var options = new JsonSerializerOptions
            {
                WriteIndented = true,
                Converters = { new JsonStringEnumConverter() }
            };
            File.WriteAllText(outputPath, JsonSerializer.Serialize(policies, options));

            Console.WriteLine();
            Console.WriteLine($"Wrote {policies.Count} approved polic{(policies.Count == 1 ? "y" : "ies")} to:");
            Console.WriteLine($"  {outputPath}");
            Console.WriteLine();
            Console.WriteLine("Each entry now includes which table it applies to. Remember to pass the");
            Console.WriteLine("matching tableName when calling conn.CreateCommand(sql, tableName: \"...\")");
            Console.WriteLine("in your application code — see SecureDb.Data's updated CreateCommand signature.");
            Console.WriteLine();
            Console.WriteLine("This is written as a SEPARATE file on purpose — it never silently overwrites");
            Console.WriteLine("a policy.json you've already hand-tuned. Review it, then merge the entries");
            Console.WriteLine("you actually want into your real policy.json.");
        }
    }
}
