# Repair usage-summary aggregation

Fix `summary.py` so `summarize_csv` satisfies the tests and these requirements:

- Group by trimmed project and trimmed, lowercase unit; sort output by both.
- Accumulate quantities with exact decimal arithmetic, preserving adjustments.
- Round once per group to two decimal places using half-even rounding and return
  a fixed two-decimal string. Support at least 30 significant decimal digits.
- Require project, unit and quantity columns. Explain missing columns with
  ValueError containing "columns". Ignore extra columns.
- Reject empty names and non-finite or invalid quantities with ValueError naming
  the CSV record's source line (the header is line 1).
- Keep the public function and return format; use only the standard library.

Edit only `summary.py`; do not edit the tests or this task. Run
`python3 -m unittest -v` and inspect the resulting diff. The reviewer will run
an independently retained copy of these tests against your changed module.
