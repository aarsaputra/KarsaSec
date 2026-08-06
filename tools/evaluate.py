#!/usr/bin/env python3
"""Automated Rule Quality Evaluator for KarsaSec Security Corpus."""

import os
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Dict, List, Set, Tuple
import yaml

# Add repository root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from karsasec.eval.runner import BenchmarkEvaluator
from karsasec.rules.loader import YAMLRuleLoader
from karsasec.rules.patterns import get_default_rules_directory

def main() -> None:
    print("============================================================")
    print("           KARSASEC AUTOMATED RULE QUALITY EVALUATOR         ")
    print("============================================================")
    
    tracemalloc.start()
    start_time = time.perf_counter()
    
    loader = YAMLRuleLoader()
    rules_dir = get_default_rules_directory()
    rules = loader.load_directory(rules_dir)
    
    evaluator = BenchmarkEvaluator()
    metrics = evaluator.evaluate()
    
    elapsed_sec = time.perf_counter() - start_time
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    print(f"Total Rules Loaded   : {len(rules)}")
    print(f"Total Samples Tested : {metrics.total_samples}")
    print(f"True Positives (TP)  : {metrics.true_positives}")
    print(f"True Negatives (TN)  : {metrics.true_negatives}")
    print(f"False Positives (FP) : {metrics.false_positives}")
    print(f"False Negatives (FN) : {metrics.false_negatives}")
    print("------------------------------------------------------------")
    print(f"Precision            : {metrics.precision * 100:.2f}% (Target >= 95.0%)")
    print(f"Recall               : {metrics.recall * 100:.2f}% (Target >= 90.0%)")
    print(f"F1 Score             : {metrics.f1_score * 100:.2f}%")
    print(f"False Positive Rate  : {metrics.false_positive_rate * 100:.2f}% (Target <= 5.0%)")
    print("------------------------------------------------------------")
    print(f"Execution Time       : {elapsed_sec:.2f} s")
    print(f"Peak Memory Usage    : {peak_mem / 1024 / 1024:.2f} MB")
    print("============================================================")
    
    if metrics.precision < 0.95 or metrics.recall < 0.90 or metrics.false_positive_rate > 0.05:
        print("[WARNING] Metrics did not satisfy production gate targets.")
    else:
        print("[SUCCESS] All metrics satisfied production gate targets.")

if __name__ == "__main__":
    main()
