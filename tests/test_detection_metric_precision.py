import unittest
from fractions import Fraction
from math import isfinite

from application import DetectionMetrics


class DetectionMetricPrecisionTests(unittest.TestCase):
    def test_equal_small_ratios_retain_representable_f1(self):
        for exponent in (155, 160, 170, 200, 300, 308, 320, 323):
            count = 10 ** exponent
            with self.subTest(exponent=exponent):
                metrics = DetectionMetrics(1, count - 1, count - 1, 0)
                self.assertEqual(metrics.f1, float(Fraction(1, count)))
                self.assertGreater(metrics.f1, 0.0)

    def test_asymmetric_ratios_use_exact_counts_near_underflow(self):
        for positives, false_positives, false_negatives in (
            (3, 10 ** 160, 10 ** 170),
            (10 ** 400, 10 ** 560, 10 ** 570),
            (1, 10 ** 324, 0),
            (1, 10 ** 325, 0),
        ):
            expected = float(Fraction(2 * positives, 2 * positives + false_positives + false_negatives))
            for left, right in ((false_positives, false_negatives), (false_negatives, false_positives)):
                with self.subTest(positives=positives, left=left, right=right):
                    metrics = DetectionMetrics(positives, left, right, 17, 91)
                    self.assertEqual(metrics.f1, expected)
                    self.assertTrue(isfinite(metrics.f1))

    def test_ordinary_results_preserve_historical_float_operations(self):
        for positives in range(1, 12):
            for false_positives in range(12):
                for false_negatives in range(12):
                    metrics = DetectionMetrics(positives, false_positives, false_negatives, 0)
                    precision, recall = metrics.precision, metrics.recall
                    self.assertEqual(metrics.f1, 2 * precision * recall / (precision + recall))

    def test_normal_product_boundary_preserves_existing_formula(self):
        for exponent in (152, 153, 154):
            count = 10 ** exponent
            metrics = DetectionMetrics(1, count - 1, count - 1, 0)
            precision, recall = metrics.precision, metrics.recall
            self.assertEqual(metrics.f1, 2 * precision * recall / (precision + recall))

    def test_undefined_results_preserve_historical_zero_sum_rule(self):
        for counts in ((0, 0, 0, 0), (0, 1, 0, 0), (0, 0, 1, 0), (0, 1, 1, 0),
                       (1, 10 ** 400, 10 ** 400, 0)):
            with self.subTest(counts=counts):
                self.assertIsNone(DetectionMetrics(*counts).f1)

    def test_repeated_reads_preserve_counts_and_excluded_counts(self):
        counts = (7, 10 ** 180, 10 ** 210, 100, 37)
        metrics = DetectionMetrics(*counts)
        expected = float(Fraction(14, 14 + counts[1] + counts[2]))
        for _ in range(3):
            self.assertEqual(metrics.f1, expected)
            self.assertEqual(metrics, DetectionMetrics(*counts))
            self.assertEqual(metrics.f1, DetectionMetrics(*counts[:3], 0).f1)


if __name__ == '__main__':
    unittest.main()
