using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Text.RegularExpressions;
using SecureDb.Core;

namespace SecureDb.Profiler
{
    /// <summary>
    /// Lightweight, explainable classifier — deliberately NOT the multi-signal confidence-model
    /// engine described in the larger R&D documents (that's real, justified effort for a
    /// product; this is scoped for "one app, a handful of tables"). Three signals combine:
    ///
    ///   1. Column NAME matches a keyword for a category         (+0.5)
    ///   2. Column DATA TYPE is plausible for that category      (+0.1, else category is rejected outright)
    ///   3. Sampled VALUES match a content pattern for the category (+0.4 * match ratio)
    ///
    /// Every recommendation always requires a human to approve it (see Program.cs) — this
    /// class only ever produces suggestions, never applies anything.
    /// </summary>
    public class ColumnClassifier
    {
        private const int SampleSize = 50;
        private readonly DbConnection _connection;

        public ColumnClassifier(DbConnection connection)
        {
            _connection = connection;
        }

        private static readonly Dictionary<string, string[]> KeywordsByCategory = new Dictionary<string, string[]>
        {
            ["EMAIL"] = new[] { "email", "mail" },
            ["PHONE"] = new[] { "phone", "mobile", "contactno", "contactnumber", "tel" },
            ["NATIONAL_ID"] = new[] { "nic", "ssn", "nationalid", "passport", "socialsecurity" },
            ["CREDIT_CARD"] = new[] { "creditcard", "cardnumber", "ccnum", "pan", "cardno" },
            ["PASSWORD"] = new[] { "password", "pwd", "secret", "apikey", "token" },
            ["SALARY"] = new[] { "salary", "wage", "income", "compensation" },
            ["DOB"] = new[] { "dob", "birthdate", "dateofbirth", "birthday" },
            ["ADDRESS"] = new[] { "address", "street", "addr" },
            ["BANK_ACCOUNT"] = new[] { "accountnumber", "bankaccount", "iban", "acctno" }
        };

        private static readonly string[] TextDataTypes =
        {
            "char", "varchar", "nvarchar", "nchar", "text", "ntext", "character varying", "character"
        };

        private static readonly string[] NumericDataTypes =
        {
            "decimal", "money", "numeric", "float", "real", "smallmoney"
        };

        private static readonly string[] DateDataTypes =
        {
            "date", "datetime", "datetime2", "smalldatetime"
        };

        private static readonly Dictionary<string, Regex[]> PatternsByCategory = new Dictionary<string, Regex[]>
        {
            ["EMAIL"] = new[] { new Regex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.Compiled) },
            ["PHONE"] = new[] { new Regex(@"^\+?[\d\-\s\(\)]{7,15}$", RegexOptions.Compiled) },
            ["NATIONAL_ID"] = new[]
            {
                new Regex(@"^\d{3}-\d{2}-\d{4}$", RegexOptions.Compiled),   // US SSN
                new Regex(@"^\d{9}[VXvx]$", RegexOptions.Compiled),        // Sri Lanka NIC (old)
                new Regex(@"^\d{12}$", RegexOptions.Compiled)              // Sri Lanka NIC (new)
            },
            ["CREDIT_CARD"] = new[] { new Regex(@"^\d{13,19}$", RegexOptions.Compiled) }
        };

        public List<ClassificationResult> ClassifyAll(List<ColumnInfo> columns)
        {
            var results = new List<ClassificationResult>();
            foreach (var col in columns)
            {
                var result = ClassifyColumn(col);
                if (result != null)
                    results.Add(result);
            }
            return results;
        }

        private ClassificationResult ClassifyColumn(ColumnInfo col)
        {
            // Hard exclusion, checked before anything else: encrypting a primary or foreign
            // key breaks joins and referential integrity outright. No keyword match or
            // confidence score can override this — it's a correctness issue, not a judgment
            // call. If a genuinely sensitive value (like a national ID) is being used AS a
            // primary key, the real fix is a surrogate key + tokenization, not encrypting
            // the key itself — flagged as a warning instead of a normal recommendation.
            if (col.IsPrimaryKey || col.IsForeignKey)
            {
                if (LooksLikelySensitiveByNameOnly(col.Column))
                {
                    return new ClassificationResult
                    {
                        Schema = col.Schema,
                        Table = col.Table,
                        Column = col.Column,
                        DataType = col.DataType,
                        Category = col.IsPrimaryKey ? "SENSITIVE_PRIMARY_KEY" : "SENSITIVE_FOREIGN_KEY",
                        Confidence = 0,
                        SuggestedMode = EncryptionMode.Random,
                        IsPasswordLike = false,
                        IsKeyColumnWarning = true
                    };
                }
                return null;
            }

            string normalizedName = col.Column.ToLowerInvariant().Replace("_", "");

            string bestCategory = null;
            double bestScore = 0;

            foreach (var pair in KeywordsByCategory)
            {
                string category = pair.Key;
                string[] keywords = pair.Value;

                bool nameMatch = false;
                foreach (var keyword in keywords)
                {
                    if (normalizedName.Contains(keyword))
                    {
                        nameMatch = true;
                        break;
                    }
                }
                if (!nameMatch)
                    continue; // only score categories with at least a naming hint

                if (!CategoryTypeMatches(category, col.DataType))
                    continue; // e.g. a column named "Email" that's actually an INT — skip it

                double score = 0.5 + 0.1; // name match + type plausibility

                if (PatternsByCategory.TryGetValue(category, out var patterns) && IsTextType(col.DataType))
                {
                    double matchRatio = SamplePatternMatchRatio(col, patterns);
                    score += 0.4 * matchRatio;
                }
                else if (category == "SALARY" || category == "DOB" || category == "BANK_ACCOUNT")
                {
                    // No reliable content pattern for these — account number formats vary
                    // too widely across banks to regex meaningfully. Name + type plausibility
                    // is the signal.
                    score += 0.3;
                }

                if (score > bestScore)
                {
                    bestScore = score;
                    bestCategory = category;
                }
            }

            if (bestCategory == null || bestScore < 0.3)
                return null;

            return new ClassificationResult
            {
                Schema = col.Schema,
                Table = col.Table,
                Column = col.Column,
                DataType = col.DataType,
                Category = bestCategory,
                Confidence = Math.Min(bestScore, 1.0),
                SuggestedMode = SuggestMode(bestCategory),
                IsPasswordLike = bestCategory == "PASSWORD"
            };
        }

        private static bool CategoryTypeMatches(string category, string dataType)
        {
            string t = dataType.ToLowerInvariant();
            switch (category)
            {
                case "EMAIL":
                case "PHONE":
                case "NATIONAL_ID":
                case "CREDIT_CARD":
                case "PASSWORD":
                case "ADDRESS":
                case "BANK_ACCOUNT":
                    return Contains(TextDataTypes, t);
                case "SALARY":
                    return Contains(NumericDataTypes, t);
                case "DOB":
                    return Contains(DateDataTypes, t);
                default:
                    return true;
            }
        }

        private static bool IsTextType(string dataType)
        {
            return Contains(TextDataTypes, dataType.ToLowerInvariant());
        }

        private static bool Contains(string[] haystack, string needleSubstring)
        {
            foreach (var item in haystack)
            {
                if (needleSubstring.Contains(item))
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Used only for the key-column safety warning: a lightweight name check (no type
        /// or pattern requirement, since a PK/FK gets excluded regardless of type) to flag
        /// "this key column's name suggests it might itself be sensitive" for a human to
        /// look at — e.g. a national ID used directly as a primary key. Never used to
        /// produce an actual encryption recommendation.
        /// </summary>
        private static bool LooksLikelySensitiveByNameOnly(string columnName)
        {
            string normalized = columnName.ToLowerInvariant().Replace("_", "");
            foreach (var keywords in KeywordsByCategory.Values)
            {
                foreach (var keyword in keywords)
                {
                    if (normalized.Contains(keyword))
                        return true;
                }
            }
            return false;
        }

        private static EncryptionMode SuggestMode(string category)
        {
            switch (category)
            {
                // Categories commonly looked up by exact match benefit from deterministic
                // encryption (WHERE col = @value keeps working) — see the tradeoffs we've
                // discussed throughout this project.
                case "EMAIL":
                case "NATIONAL_ID":
                case "CREDIT_CARD":
                case "BANK_ACCOUNT":
                    return EncryptionMode.Deterministic;
                default:
                    return EncryptionMode.Random;
            }
        }

        private double SamplePatternMatchRatio(ColumnInfo col, Regex[] patterns)
        {
            List<string> values = SampleValues(col);
            if (values.Count == 0)
                return 0;

            int matches = 0;
            foreach (var value in values)
            {
                if (string.IsNullOrWhiteSpace(value))
                    continue;

                string trimmed = value.Trim();
                foreach (var pattern in patterns)
                {
                    if (pattern.IsMatch(trimmed))
                    {
                        matches++;
                        break;
                    }
                }
            }

            return (double)matches / values.Count;
        }

        private List<string> SampleValues(ColumnInfo col)
        {
            var values = new List<string>();
            try
            {
                using (var cmd = _connection.CreateCommand())
                {
                    // Deliberately no TOP/LIMIT here — that syntax differs per database engine
                    // (TOP for SQL Server, LIMIT for Postgres/MySQL). Reading only the first
                    // SampleSize rows from the reader and stopping works identically on every
                    // provider without any dialect-specific SQL. For very large tables, a
                    // production version should add provider-specific LIMIT/TOP/FETCH FIRST
                    // to avoid the server planning a full scan — noted here, not solved here.
                    cmd.CommandText = $"SELECT {col.Column} FROM {col.Schema}.{col.Table}";

                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read() && values.Count < SampleSize)
                        {
                            if (!reader.IsDBNull(0))
                                values.Add(reader.GetValue(0).ToString());
                        }
                    }
                }
            }
            catch
            {
                // If sampling fails for any reason (permissions, an odd column, a locked
                // table, etc.), just skip pattern-based scoring for this one column rather
                // than crashing the entire scan.
            }
            return values;
        }
    }
}
