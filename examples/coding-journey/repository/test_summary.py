import unittest
from summary import summarize_csv


class SummaryTests(unittest.TestCase):
    def test_combines_matching_records_exactly(self):
        self.assertEqual(summarize_csv("project,unit,quantity\na,tokens,0.1\na,tokens,0.2\n"),
                         [{"project": "a", "unit": "tokens", "quantity": "0.30"}])

    def test_rounds_once_after_aggregation(self):
        self.assertEqual(summarize_csv("project,unit,quantity\na,cpu_seconds,0.005\na,cpu_seconds,0.005\n"),
                         [{"project": "a", "unit": "cpu_seconds", "quantity": "0.01"}])

    def test_normalizes_names_and_sorts_groups(self):
        text = "project,unit,quantity\nz,tokens,2\n a ,TOKENS,1\na,tokens,2\na,cpu_seconds,4\n"
        self.assertEqual(summarize_csv(text), [
            {"project": "a", "unit": "cpu_seconds", "quantity": "4.00"},
            {"project": "a", "unit": "tokens", "quantity": "3.00"},
            {"project": "z", "unit": "tokens", "quantity": "2.00"},
        ])

    def test_preserves_large_exact_quantities(self):
        whole = "1" + "0" * 27
        text = f"project,unit,quantity\na,tokens,{whole}.01\na,tokens,0.01\n"
        self.assertEqual(summarize_csv(text)[0]["quantity"], whole + ".02")

    def test_adjustments_and_half_even_rounding(self):
        text = "project,unit,quantity\na,tokens,2.355\na,tokens,-1.00\n"
        self.assertEqual(summarize_csv(text)[0]["quantity"], "1.36")

    def test_empty_input_with_header(self):
        self.assertEqual(summarize_csv("project,unit,quantity\n"), [])

    def test_invalid_records_name_the_csv_line(self):
        for quantity in ("NaN", "Infinity", "-Infinity", "bad", ""):
            with self.subTest(quantity=quantity):
                with self.assertRaisesRegex(ValueError, "line 2"):
                    summarize_csv(f"project,unit,quantity\na,tokens,{quantity}\n")

    def test_missing_columns_are_explained(self):
        with self.assertRaisesRegex(ValueError, "columns"):
            summarize_csv("project,quantity\na,1\n")

    def test_empty_names_are_explained(self):
        for row in (",tokens,1", "a, ,1"):
            with self.assertRaisesRegex(ValueError, "line 2"):
                summarize_csv("project,unit,quantity\n" + row + "\n")


if __name__ == "__main__":
    unittest.main()
