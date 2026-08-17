# Sample Existing App — Full SecureDb Scenario Test

A genuinely separate, more realistic test bed for everything built in the SecureDb project.
Where the original `SecureDbPrototype` solution used one simple table to prove each idea
individually, this one uses a small but realistic multi-table schema to prove they all work
**together**, including the safety guards that only matter once you have more than one table.

## What's different about this schema, on purpose

- **Foreign keys**: `Employee.DepartmentID` → `Department`, `BankDetails.EmployeeID` → `Employee`.
  Tests that the Profiler's key-exclusion safety guard actually fires.
- **A same-named column in two different tables**: both `Employee` and `Vendor` have an
  `Email` column. `policy.json` protects `Employee.Email` but deliberately does **not**
  protect `Vendor.Email` — proving table-qualified policy actually works, not just in theory.
- **A deliberately bad column**: `Employee.Password`, stored as plain text — exists purely to
  prove the Profiler's "this looks like a password, hash it instead" warning fires correctly.
- **A financial field with no content-pattern check**: `BankDetails.AccountNumber` — added a
  new `BANK_ACCOUNT` classification category to handle this, since it didn't exist before this
  schema exposed the gap.
- **Pre-seeded plaintext data** in every table — simulating a real "already existing app" that
  already has data, not an empty table you're inserting into for the first time.

## Setup

1. Run `sql/companydb-setup.sql` against your SQL Server instance — creates `CompanyDB` with
   all four tables and seed data.
2. Open `SampleExistingApp.sln` in Visual Studio.

## The full test sequence

**Step 1 — Identify.** Set `SecureDb.Profiler` as the startup project, run it. Expect to see:
- A key-column warning section (informational only) — likely empty here, since none of the
  FK/PK columns happen to look sensitive by name in this schema; this is exactly the
  "excluded, not merely unlikely" guarantee in action.
- `Employee.Password` flagged with the hashing warning.
- `Employee.Email`, `Employee.NIC`, `Employee.Salary`, `Employee.DateOfBirth`,
  `BankDetails.AccountNumber`, and `Vendor.Email`/`Vendor.Phone` recommended, each with a
  confidence level.
- `database-identity-report.json` written, listing every table/column/key found.

Only approve `Employee.Email`, `Employee.NIC`, and `BankDetails.AccountNumber` when prompted —
these are the three already set up in `SampleExistingApp.WinForms/policy.json`. (Feel free to
experiment with approving others too — just know `Employee.Salary`/`DateOfBirth` would need a
schema type change from decimal/date to text, which breaks any code expecting a real number or
date back — see the main technical documentation's discussion of this exact trade-off.)

**Step 2 — Prepare the schema.** Run `sql/alter-for-encryption.sql` — widens exactly the three
columns actually being protected.

**Step 3 — Migrate existing data.** Set `SecureDb.MigrationTool` as the startup project, run
it. It should process all three policy entries in one run, encrypting the seed data already
sitting in `Employee` and `BankDetails`.

**Step 4 — Run the actual application.** Set `SampleExistingApp.WinForms` as the startup
project, run it.
- Click **"Load All Data (via App — decrypted)"** — Employee/BankDetails values should show
  plain text (decrypted transparently), and Vendor emails should also show plain text (never
  encrypted in the first place).
- Click **"Show Raw From DB (bypass wrapper)"** — Employee `Email`/`NIC` and BankDetails
  `AccountNumber` should now show unreadable ciphertext. Vendor `Email` should still show
  plain text here too — the definitive proof that table-qualified policy is actually
  discriminating between the two `Email` columns, not applying blanket rules by column name.
- Try adding a new Employee and a new Vendor through the form — confirm new data follows the
  same pattern as the migrated seed data.

## Honest status

**Not run or compiled on my end** — same standing caveat as everything else in this project.
This is the most structurally complex piece built so far (5 projects, a WinForms UI with no
visual designer file, real foreign keys), so budget extra time for a first debugging pass.
Send me the Error List or whatever the app actually does, and we'll fix it from there.
