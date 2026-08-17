using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecureDb.Core
{
    /// <summary>
    /// Loads column protection policy from policy.json.
    ///
    /// Supports two kinds of rules, and prefers the more specific one when both exist:
    ///   - Table-qualified: applies only to a specific (TableName, ColumnName) pair.
    ///   - Column-only (TableName left null/empty): applies to any table with that column
    ///     name — this is the original behavior, kept for backward compatibility with
    ///     existing policy.json files that don't specify a table.
    /// </summary>
    public class PolicyStore
    {
        private readonly Dictionary<string, ColumnPolicy> _byTableAndColumn =
            new Dictionary<string, ColumnPolicy>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, ColumnPolicy> _byColumnNameOnly =
            new Dictionary<string, ColumnPolicy>(StringComparer.OrdinalIgnoreCase);

        public PolicyStore(string policyFilePath)
        {
            if (!File.Exists(policyFilePath))
                throw new FileNotFoundException($"Policy file not found: {policyFilePath}");

            string json = File.ReadAllText(policyFilePath);
            var options = new JsonSerializerOptions
            {
                Converters = { new JsonStringEnumConverter() }
            };
            var policies = JsonSerializer.Deserialize<List<ColumnPolicy>>(json, options) ?? new List<ColumnPolicy>();

            foreach (var policy in policies)
            {
                if (!policy.Enabled)
                    continue;

                if (!string.IsNullOrWhiteSpace(policy.TableName))
                    _byTableAndColumn[TableColumnKey(policy.TableName, policy.ColumnName)] = policy;
                else
                    _byColumnNameOnly[policy.ColumnName] = policy;
            }
        }

        /// <summary>
        /// Original lookup — column name only. Still works exactly as before for any
        /// existing policy.json that doesn't use TableName. If a table-qualified rule
        /// exists for that column name under ANY table, this can't disambiguate — use
        /// the (columnName, tableName) overload below when you know the table.
        /// </summary>
        public bool TryGetPolicy(string columnName, out ColumnPolicy policy)
        {
            return _byColumnNameOnly.TryGetValue(columnName, out policy);
        }

        /// <summary>
        /// Table-aware lookup: checks for a rule specific to (tableName, columnName) first;
        /// if none exists, falls back to a column-only rule (applies to any table). This is
        /// what lets Customer.Email and Vendor.Email be governed by different rules once you
        /// actually know which table you're operating on.
        /// </summary>
        public bool TryGetPolicy(string columnName, string tableName, out ColumnPolicy policy)
        {
            if (!string.IsNullOrWhiteSpace(tableName) &&
                _byTableAndColumn.TryGetValue(TableColumnKey(tableName, columnName), out policy))
            {
                return true;
            }

            return _byColumnNameOnly.TryGetValue(columnName, out policy);
        }

        public IEnumerable<ColumnPolicy> AllPolicies
        {
            get
            {
                foreach (var p in _byTableAndColumn.Values) yield return p;
                foreach (var p in _byColumnNameOnly.Values) yield return p;
            }
        }

        private static string TableColumnKey(string table, string column) => $"{table}::{column}";
    }
}
