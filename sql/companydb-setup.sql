-- ============================================================================
-- CompanyDB — a separate, more realistic test database for SecureDb.
-- Multiple tables, real foreign keys, a same-named column ("Email"/"Phone")
-- appearing in two DIFFERENT tables, and a deliberately bad plaintext
-- "Password" column — all included on purpose to exercise every safety
-- guard and feature built so far, not just the happy path.
-- ============================================================================

IF DB_ID('CompanyDB') IS NULL
    CREATE DATABASE CompanyDB;
GO

USE CompanyDB;
GO

IF OBJECT_ID('dbo.BankDetails', 'U') IS NOT NULL DROP TABLE dbo.BankDetails;
IF OBJECT_ID('dbo.Employee', 'U') IS NOT NULL DROP TABLE dbo.Employee;
IF OBJECT_ID('dbo.Department', 'U') IS NOT NULL DROP TABLE dbo.Department;
IF OBJECT_ID('dbo.Vendor', 'U') IS NOT NULL DROP TABLE dbo.Vendor;
GO

CREATE TABLE dbo.Department
(
    DepartmentID   INT IDENTITY(1,1) PRIMARY KEY,
    DepartmentName VARCHAR(100) NOT NULL
);

CREATE TABLE dbo.Employee
(
    EmployeeID   INT IDENTITY(1,1) PRIMARY KEY,
    DepartmentID INT NOT NULL FOREIGN KEY REFERENCES dbo.Department(DepartmentID),
    FullName     VARCHAR(100) NOT NULL,
    Email        VARCHAR(100) NOT NULL,   -- same column name as Vendor.Email, deliberately
    Phone        VARCHAR(20)  NULL,       -- same column name as Vendor.Phone, deliberately
    NIC          VARCHAR(20)  NOT NULL,
    DateOfBirth  DATE         NULL,
    Salary       DECIMAL(10,2) NOT NULL,
    Password     VARCHAR(50)  NOT NULL    -- deliberately bad: plaintext password column,
                                           -- included to prove the Profiler's warning fires
);

CREATE TABLE dbo.BankDetails
(
    BankDetailID  INT IDENTITY(1,1) PRIMARY KEY,
    EmployeeID    INT NOT NULL FOREIGN KEY REFERENCES dbo.Employee(EmployeeID),
    AccountNumber VARCHAR(30)  NOT NULL,
    BankName      VARCHAR(100) NOT NULL
);

CREATE TABLE dbo.Vendor
(
    VendorID   INT IDENTITY(1,1) PRIMARY KEY,
    VendorName VARCHAR(100) NOT NULL,
    Email      VARCHAR(100) NOT NULL,     -- same column name as Employee.Email, deliberately
    Phone      VARCHAR(20)  NULL          -- same column name as Employee.Phone, deliberately
);
GO

-- Seed data — deliberately PLAINTEXT, simulating an application that already has real data
-- sitting in it before SecureDb is retrofitted onto it (see SecureDb.MigrationTool below).

INSERT INTO dbo.Department (DepartmentName) VALUES ('Engineering'), ('Finance'), ('Human Resources');

INSERT INTO dbo.Employee (DepartmentID, FullName, Email, Phone, NIC, DateOfBirth, Salary, Password)
VALUES
    (1, 'Nimal Perera',    'nimal.perera@company.com',   '0771234567', '991234567V', '1985-03-12', 185000.00, 'Passw0rd!'),
    (2, 'Kamala Silva',    'kamala.silva@company.com',   '0719876543', '199012345678', '1990-07-25', 210000.00, 'Kamala@2024'),
    (3, 'Sunil Fernando',  'sunil.fernando@company.com', '0765551234', '881234567V', '1988-11-02', 165000.00, 'SunilF#123');

INSERT INTO dbo.BankDetails (EmployeeID, AccountNumber, BankName)
VALUES
    (1, '8001234567', 'Bank of Ceylon'),
    (2, '8007654321', 'Commercial Bank'),
    (3, '8009988776', 'Sampath Bank');

INSERT INTO dbo.Vendor (VendorName, Email, Phone)
VALUES
    ('Acme Office Supplies', 'contact@acmeoffice.com', '0112223344'),
    ('BlueWave IT Services',  'sales@bluewaveit.com',   '0117778899');
GO

PRINT 'CompanyDB created and seeded.';
