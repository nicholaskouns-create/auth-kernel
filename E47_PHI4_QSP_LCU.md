# E₄₇ Φ₄ · quantum circuit cross-repository packet

**Shared new result, sourced from E47-Kartekeya.** Exact finite algebra (E0) and locally executed NumPy 125D/250D/500D simulation (E1), 14/14 checks. This repository does not claim an independent replay.

### Exact factorization

Q₄(s) = 1 − (2176/353)s² + (2048/353)s⁴.

P(s) = Q₄(s) + (272i/353)s².

R(s) = s(2048s² − 1152 + 16i√817)/353.

|P(s)|² + (1−s²)|R(s)|² = 1 for real s.

Φ₄ ≈ (0, 0.618892044578, 0.439842582816, −0.179049461762, 0) rad.

### Circuit and selected block

A = |(C−6I)(C−30I)|/432 on H = V₂⊗³, dim H=125.

W₂₅₀(A) = [[A,i√(I−A²)],[i√(I−A²),A]].

U₂₅₀ = Z(φ₀)WZ(φ₁)WZ(φ₂)WZ(φ₃)WZ(φ₄).

V₅₀₀ = (H₂⊗I₂₅₀) diag(U₂₅₀,U₂₅₀†) (H₂⊗I₂₅₀).

⟨0_LCU,0_signal|V₅₀₀|0_LCU,0_signal⟩ = Q₄(A).

‖Q₄(A)−P₄₇‖₂ = 225/353.

The selected block is postselected, not an automatically deterministic quantum channel. The 500D block construction does not certify a native 9-qubit gate decomposition, physical device execution, or a computational speedup.

### Canonical independent sources

- [Interactive full circuit](https://nicholaskouns-create.github.io/E47-Kartekeya/interfaces/qsvt-phi4-circuit/)
- [Full-screen Mathematical City embed](https://nicholaskouns-create.github.io/qsvt-phi4/)
- [Complete derivation](https://github.com/nicholaskouns-create/E47-Kartekeya/blob/main/research/e47/qsp_phi4/README.md)
- [Executable NumPy certificate](https://github.com/nicholaskouns-create/E47-Kartekeya/blob/main/research/e47/qsp_phi4/e47_phi4_cg_lcu_certificate.py)
- [Machine-readable receipt](https://github.com/nicholaskouns-create/E47-Kartekeya/blob/main/research/e47/qsp_phi4/e47_phi4_cg_lcu_receipt.json)

### Local application boundary

This is quantum-signal-processing mathematics, not an authorization, encryption, or runtime-security guarantee.
