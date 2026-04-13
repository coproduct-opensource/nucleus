# Notebooks

Interactive demonstrations of the nucleus formal framework.

## Available notebooks

### [`lean_in_colab.ipynb`](lean_in_colab.ipynb)

**Actually runs the Lean 4 formalization in Colab.** Installs `elan`,
clones the repo, fetches cached Mathlib oleans, and builds
`AlignmentTaxBridge` — the file containing the Alignment Tax Theorem.

Runtime: ~5-10 minutes. Anyone with a browser can verify the proofs.

### [`alignment_tax_demo.ipynb`](alignment_tax_demo.ipynb)

Demonstrates the **Alignment Tax Theorem** (`alignmentTaxH1_eq_operational` in `AlignmentTaxBridge.lean`):

> The minimum number of declassifications required to globally realise
> capability under an IFC policy equals the rank of the first Čech
> cohomology group of the IFC sheaf.

Shows empirical verification on four canonical examples:
- **Diamond**: pairwise disagreement — rank H¹ = 2, operational tax = 2
- **DirectInject**: secure — rank H¹ = 0, no declassifications needed
- **Borromean**: triple-collusion — rank H¹ = 90, rank H² = 64
- **Universal detection impossibility**: Rice-style obstruction to any bounded detector

## Running in Google Colab

Open any notebook directly in Colab:

```
https://colab.research.google.com/github/coproduct-opensource/nucleus/blob/main/notebooks/alignment_tax_demo.ipynb
```

No setup required — pure Python 3, no dependencies beyond standard library.

## The Lean formalization

Each notebook cross-references the Lean 4 theorem it demonstrates. The
formalization lives in [`crates/portcullis-core/lean/`](../crates/portcullis-core/lean/)
and is machine-checked modulo one structural axiom (Gaussian elimination
correctness over GF(2)) — the single remaining open problem for
unconditional closure of the Alignment Tax Theorem.

## Contributing

- Add new examples to `alignment_tax_demo.ipynb` or create a new notebook.
- Cross-reference to specific Lean theorems by name.
- Keep notebooks runnable in Colab (no nonstandard dependencies).
