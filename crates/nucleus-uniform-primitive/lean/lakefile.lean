import Lake
open Lake DSL

-- Uniform-primitive composition SPINE (RESEARCH tier).
--
-- Mathlib-free (finite structural logic only; builds in seconds, no warm cache).
-- The composition theorem `preserves_seq` is PROVEN sorry-free AND axiom-free.
-- The four LAYER BRIDGES of the nucleus refinement stack (policy -> ocap ->
-- ISA -> kernel -> CHERI hardware) are named `axiom`s: each stands for a layer
-- whose operational semantics is not yet modeled here. Their COUNT is the
-- machine-checked distance-to-done, ratcheted by `uniform-primitive-lean.yml`
-- against `.uniform-primitive-axiom-baseline`. This is the research-tier analogue
-- of the proven-tier zero-axiom `Ifc` lib and the sorry-ratcheted portcullis-core
-- research cluster: axioms are ALLOWED here but may only ever go DOWN.
package «nucleusUniformPrimitive» where
  leanOptions := #[⟨`autoImplicit, false⟩]

@[default_target]
lean_lib «UniformPrimitive» where
  roots := #[`UniformPrimitive]
