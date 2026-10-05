"""Summarize ordinary CSV usage records by project and unit."""
import csv
import io


def summarize_csv(text):
    totals = {}
    for row in csv.DictReader(io.StringIO(text)):
        key = (row["project"], row["unit"])
        totals[key] = totals.get(key, 0.0) + float(row["quantity"])
    return [
        {"project": project, "unit": unit, "quantity": str(round(quantity, 2))}
        for (project, unit), quantity in totals.items()
    ]
