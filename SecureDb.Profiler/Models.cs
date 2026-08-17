namespace SecureDb.Profiler
{
    // ColumnInfo now lives in SecureDb.Core (shared with SecureDb.MigrationTool) — see
    // SecureDb.Core/Models.cs. Only the Profiler-specific classification result stays here.

    /// <summary>The profiler's recommendation for one column.</summary>
    public class ClassificationResult
    {
        public string Schema { get; set; }
        public string Table { get; set; }
        public string Column { get; set; }
        public string DataType { get; set; }
        public string Category { get; set; }
        public double Confidence { get; set; }
        public SecureDb.Core.EncryptionMode SuggestedMode { get; set; }
        public bool IsPasswordLike { get; set; }
        public bool IsKeyColumnWarning { get; set; }
    }
}
