# KarsaSec Qualification Metrics Specification

Standard equations and zero-division policies used by the `karsasec.qualification` system.

---

## Formulas

### 1. Precision
$$\text{Precision} = \frac{TP}{TP + FP}$$

- **Meaning**: What percentage of findings emitted by KarsaSec are genuine vulnerabilities?
- **Zero-Division Policy**: If $TP + FP = 0$, Precision $= 0.0$.

### 2. Recall
$$\text{Recall} = \frac{TP}{TP + FN}$$

- **Meaning**: What percentage of real vulnerabilities in the target application were detected?
- **Zero-Division Policy**: If $TP + FN = 0$, Recall $= 0.0$.

### 3. F1 Score
$$\text{F1} = \frac{2 \times \text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$

- **Meaning**: Harmonic mean of Precision and Recall.
- **Zero-Division Policy**: If $\text{Precision} + \text{Recall} = 0.0$, F1 $= 0.0$.

### 4. Duplicate Finding Rate
$$\text{Duplicate Rate} = \frac{\text{Raw Findings} - \text{Final Findings}}{\text{Raw Findings}}$$

- **Meaning**: Quantifies deduplication efficiency from `FindingCorrelator`.
- **Zero-Division Policy**: If $\text{Raw Findings} = 0$, Duplicate Rate $= 0.0$.
