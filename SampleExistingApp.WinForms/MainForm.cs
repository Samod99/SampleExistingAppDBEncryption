using System;
using System.Data.Common;
using System.Drawing;
using System.Windows.Forms;
using Microsoft.Data.SqlClient;
using SecureDb.Core;
using SecureDb.Data;

namespace SampleExistingApp.WinForms
{
    /// <summary>
    /// Stand-in for "an application that already exists." Manages Employees and Vendors
    /// against CompanyDB. Already wired up to SecureDb (representing the END state after
    /// following the 8-phase integration process) so running it demonstrates the whole
    /// pipeline working, not just individual pieces.
    ///
    /// Deliberately demonstrates table-qualified policy directly: Employee.Email is
    /// protected, Vendor.Email is NOT, even though both tables have a column literally
    /// named "Email" — this only works correctly because tableName is passed to
    /// CreateCommand(...) everywhere below.
    ///
    /// All controls are created in code rather than a separate Designer.cs file — this
    /// avoids the specific risk of a hand-written designer file being subtly inconsistent
    /// with its partial class (a common source of "designer file corrupted" errors), at the
    /// cost of not being editable in the visual designer. Fully valid, compilable WinForms
    /// either way.
    /// </summary>
    public class MainForm : Form
    {
        private TextBox _empFullName, _empEmail, _empPhone, _empNic, _empSalary, _empPassword, _empAccountNumber, _empBankName;
        private ComboBox _empDepartment;
        private TextBox _vendorName, _vendorEmail, _vendorPhone;
        private TextBox _output;

        private SecureDbConnection _conn;
        private PolicyStore _policyStore;
        private KeyManager _keyManager;
        private const string ConnectionString =
            @"Server=localhost\SQLEXPRESS;Database=CompanyDB;Integrated Security=true;TrustServerCertificate=true;";

        public MainForm()
        {
            Text = "Sample Existing App — Employee & Vendor Management (SecureDb-enabled)";
            Width = 900;
            Height = 750;
            StartPosition = FormStartPosition.CenterScreen;

            BuildUi();
            InitializeSecureDb();
        }

        private void InitializeSecureDb()
        {
            _keyManager = new KeyManager(@"C:\ProgramData\SampleExistingApp");
            _policyStore = new PolicyStore(System.IO.Path.Combine(Application.StartupPath, "policy.json"));
        }

        private SecureDbConnection OpenConnection()
        {
            DbConnection real = new SqlConnection(ConnectionString);
            var conn = new SecureDbConnection(real, _policyStore, _keyManager);
            conn.Open();
            return conn;
        }

        // ---------------------------------------------------------------- UI construction

        private void BuildUi()
        {
            var mainLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1 };
            mainLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            mainLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            Controls.Add(mainLayout);

            mainLayout.Controls.Add(BuildEmployeeGroup(), 0, 0);
            mainLayout.Controls.Add(BuildVendorAndOutputPanel(), 1, 0);
        }

        private GroupBox BuildEmployeeGroup()
        {
            var group = new GroupBox { Text = "Add Employee", Dock = DockStyle.Fill, Padding = new Padding(10) };
            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, AutoSize = true };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

            _empDepartment = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Fill };
            _empDepartment.Items.AddRange(new object[] { "1 - Engineering", "2 - Finance", "3 - Human Resources" });
            _empDepartment.SelectedIndex = 0;

            _empFullName = NewTextBox();
            _empEmail = NewTextBox();
            _empPhone = NewTextBox();
            _empNic = NewTextBox();
            _empSalary = NewTextBox();
            _empPassword = NewTextBox();
            _empAccountNumber = NewTextBox();
            _empBankName = NewTextBox();

            AddRow(layout, "Department:", _empDepartment);
            AddRow(layout, "Full Name:", _empFullName);
            AddRow(layout, "Email:", _empEmail);
            AddRow(layout, "Phone:", _empPhone);
            AddRow(layout, "NIC:", _empNic);
            AddRow(layout, "Salary:", _empSalary);
            AddRow(layout, "Password:", _empPassword);
            AddRow(layout, "Bank Account #:", _empAccountNumber);
            AddRow(layout, "Bank Name:", _empBankName);

            var saveButton = new Button { Text = "Save Employee (+ Bank Details)", AutoSize = true, Margin = new Padding(0, 10, 0, 0) };
            saveButton.Click += SaveEmployee_Click;
            layout.Controls.Add(new Label(), 0, layout.RowCount);
            layout.Controls.Add(saveButton, 1, layout.RowCount);
            layout.RowCount++;

            group.Controls.Add(layout);
            return group;
        }

        private Control BuildVendorAndOutputPanel()
        {
            var outer = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 3 };
            outer.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            outer.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            outer.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            var vendorGroup = new GroupBox { Text = "Add Vendor", Dock = DockStyle.Fill, Padding = new Padding(10), AutoSize = true };
            var vLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, AutoSize = true };
            vLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));
            vLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

            _vendorName = NewTextBox();
            _vendorEmail = NewTextBox();
            _vendorPhone = NewTextBox();
            AddRow(vLayout, "Vendor Name:", _vendorName);
            AddRow(vLayout, "Email:", _vendorEmail);
            AddRow(vLayout, "Phone:", _vendorPhone);

            var saveVendorButton = new Button { Text = "Save Vendor", AutoSize = true, Margin = new Padding(0, 10, 0, 0) };
            saveVendorButton.Click += SaveVendor_Click;
            vLayout.Controls.Add(new Label(), 0, vLayout.RowCount);
            vLayout.Controls.Add(saveVendorButton, 1, vLayout.RowCount);
            vLayout.RowCount++;
            vendorGroup.Controls.Add(vLayout);

            var buttonsPanel = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, Padding = new Padding(0, 10, 0, 10) };
            var loadDecryptedButton = new Button { Text = "Load All Data (via App — decrypted)", AutoSize = true };
            loadDecryptedButton.Click += LoadDecrypted_Click;
            var loadRawButton = new Button { Text = "Show Raw From DB (bypass wrapper)", AutoSize = true };
            loadRawButton.Click += LoadRaw_Click;
            buttonsPanel.Controls.Add(loadDecryptedButton);
            buttonsPanel.Controls.Add(loadRawButton);

            _output = new TextBox
            {
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                Dock = DockStyle.Fill,
                Font = new Font("Consolas", 9)
            };

            outer.Controls.Add(vendorGroup, 0, 0);
            outer.Controls.Add(buttonsPanel, 0, 1);
            outer.Controls.Add(_output, 0, 2);
            return outer;
        }

        private static TextBox NewTextBox() => new TextBox { Dock = DockStyle.Fill, Margin = new Padding(3, 3, 10, 3) };

        private static void AddRow(TableLayoutPanel layout, string labelText, Control input)
        {
            int row = layout.RowCount;
            layout.RowCount++;
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.Controls.Add(new Label { Text = labelText, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 6, 3, 3) }, 0, row);
            layout.Controls.Add(input, 1, row);
        }

        // ---------------------------------------------------------------- Actions

        private void SaveEmployee_Click(object sender, EventArgs e)
        {
            try
            {
                int departmentId = _empDepartment.SelectedIndex + 1;

                using (var conn = OpenConnection())
                {
                    int newEmployeeId;
                    using (var cmd = conn.CreateCommand(
                        "INSERT INTO Employee (DepartmentID, FullName, Email, Phone, NIC, Salary, Password) " +
                        "OUTPUT INSERTED.EmployeeID " +
                        "VALUES (@DepartmentID, @FullName, @Email, @Phone, @NIC, @Salary, @Password)",
                        tableName: "Employee"))
                    {
                        cmd.AddParameter("@DepartmentID", departmentId);
                        cmd.AddParameter("@FullName", _empFullName.Text);
                        cmd.AddParameter("@Email", _empEmail.Text);       // protected — Employee.Email has a policy entry
                        cmd.AddParameter("@Phone", _empPhone.Text);
                        cmd.AddParameter("@NIC", _empNic.Text);           // protected
                        cmd.AddParameter("@Salary", decimal.Parse(string.IsNullOrWhiteSpace(_empSalary.Text) ? "0" : _empSalary.Text));
                        cmd.AddParameter("@Password", _empPassword.Text); // NOT in policy.json on purpose — see README
                        newEmployeeId = (int)cmd.ExecuteScalar();
                    }

                    if (!string.IsNullOrWhiteSpace(_empAccountNumber.Text))
                    {
                        using (var bankCmd = conn.CreateCommand(
                            "INSERT INTO BankDetails (EmployeeID, AccountNumber, BankName) VALUES (@EmployeeID, @AccountNumber, @BankName)",
                            tableName: "BankDetails"))
                        {
                            bankCmd.AddParameter("@EmployeeID", newEmployeeId);
                            bankCmd.AddParameter("@AccountNumber", _empAccountNumber.Text); // protected
                            bankCmd.AddParameter("@BankName", _empBankName.Text);
                            bankCmd.ExecuteNonQuery();
                        }
                    }
                }

                MessageBox.Show(this, "Employee saved.", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error saving employee", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void SaveVendor_Click(object sender, EventArgs e)
        {
            try
            {
                using (var conn = OpenConnection())
                using (var cmd = conn.CreateCommand(
                    "INSERT INTO Vendor (VendorName, Email, Phone) VALUES (@VendorName, @Email, @Phone)",
                    tableName: "Vendor"))
                {
                    cmd.AddParameter("@VendorName", _vendorName.Text);
                    cmd.AddParameter("@Email", _vendorEmail.Text); // NOT protected — no Vendor.Email policy entry, by design
                    cmd.AddParameter("@Phone", _vendorPhone.Text);
                    cmd.ExecuteNonQuery();
                }

                MessageBox.Show(this, "Vendor saved.", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, ex.Message, "Error saving vendor", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void LoadDecrypted_Click(object sender, EventArgs e)
        {
            try
            {
                var sb = new System.Text.StringBuilder();
                sb.AppendLine("=== Employees (via SecureDb wrapper — should show PLAIN TEXT) ===");

                using (var conn = OpenConnection())
                {
                    using (var cmd = conn.CreateCommand(
                        "SELECT FullName, Email, Phone, NIC, Salary FROM Employee", tableName: "Employee"))
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            sb.AppendLine($"  {reader["FullName"]} | {reader["Email"]} | {reader["Phone"]} | NIC={reader["NIC"]} | Salary={reader["Salary"]}");
                        }
                    }

                    sb.AppendLine();
                    sb.AppendLine("=== Bank Details (AccountNumber should show PLAIN TEXT) ===");
                    using (var cmd = conn.CreateCommand(
                        "SELECT AccountNumber, BankName FROM BankDetails", tableName: "BankDetails"))
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            sb.AppendLine($"  {reader["AccountNumber"]} | {reader["BankName"]}");
                        }
                    }

                    sb.AppendLine();
                    sb.AppendLine("=== Vendors (Email should ALSO show PLAIN TEXT, but for a different reason —");
                    sb.AppendLine("=== it was never encrypted at all, since Vendor.Email has no policy entry) ===");
                    using (var cmd = conn.CreateCommand(
                        "SELECT VendorName, Email, Phone FROM Vendor", tableName: "Vendor"))
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            sb.AppendLine($"  {reader["VendorName"]} | {reader["Email"]} | {reader["Phone"]}");
                        }
                    }
                }

                _output.Text = sb.ToString();
            }
            catch (Exception ex)
            {
                _output.Text = "ERROR: " + ex.Message;
            }
        }

        private void LoadRaw_Click(object sender, EventArgs e)
        {
            try
            {
                var sb = new System.Text.StringBuilder();
                sb.AppendLine("=== Employees, RAW from SQL Server (wrapper bypassed) ===");
                sb.AppendLine("=== Email/NIC should show CIPHERTEXT here — this is the actual proof ===");

                using (var rawConn = new SqlConnection(ConnectionString))
                {
                    rawConn.Open();

                    using (var cmd = rawConn.CreateCommand())
                    {
                        cmd.CommandText = "SELECT FullName, Email, Phone, NIC, Salary FROM Employee";
                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                sb.AppendLine($"  {reader["FullName"]} | {reader["Email"]} | {reader["Phone"]} | NIC={reader["NIC"]} | Salary={reader["Salary"]}");
                            }
                        }
                    }

                    sb.AppendLine();
                    sb.AppendLine("=== Bank Details, RAW (AccountNumber should show CIPHERTEXT) ===");
                    using (var cmd = rawConn.CreateCommand())
                    {
                        cmd.CommandText = "SELECT AccountNumber, BankName FROM BankDetails";
                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                sb.AppendLine($"  {reader["AccountNumber"]} | {reader["BankName"]}");
                            }
                        }
                    }

                    sb.AppendLine();
                    sb.AppendLine("=== Vendors, RAW (Email should show PLAIN TEXT — never encrypted) ===");
                    using (var cmd = rawConn.CreateCommand())
                    {
                        cmd.CommandText = "SELECT VendorName, Email, Phone FROM Vendor";
                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                sb.AppendLine($"  {reader["VendorName"]} | {reader["Email"]} | {reader["Phone"]}");
                            }
                        }
                    }
                }

                _output.Text = sb.ToString();
            }
            catch (Exception ex)
            {
                _output.Text = "ERROR: " + ex.Message;
            }
        }
    }
}
