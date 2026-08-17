USE CompanyDB;
GO

-- Widen exactly the three columns that policy.json actually protects.
-- Everything else (FullName, DepartmentName, VendorName, Phone, Salary, DateOfBirth,
-- Password, BankName) stays as-is — either not sensitive, or excluded for reasons
-- explained in README.md (numeric/date type change risk, password should be hashed).

ALTER TABLE Employee ALTER COLUMN Email NVARCHAR(MAX) NOT NULL;
ALTER TABLE Employee ALTER COLUMN NIC NVARCHAR(MAX) NOT NULL;
ALTER TABLE BankDetails ALTER COLUMN AccountNumber NVARCHAR(MAX) NOT NULL;
GO

PRINT 'Schema widened for encryption.';
