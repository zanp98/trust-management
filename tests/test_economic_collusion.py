import csv
import unittest
from pathlib import Path

from tests.simulations.economic_collusion import analyse_collusion, load_votes


class EconomicCollusionTests(unittest.TestCase):
    def _write_csv(self, rows, tmp_path: Path) -> Path:
        path = tmp_path / "sample.csv"
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["Evaluator", "Entity", "CombinedDecision"])
            writer.writerows(rows)
        return path

    def test_flags_insufficient_evaluators(self):
        with self.subTest("single evaluator is flagged"):
            from tempfile import TemporaryDirectory

            with TemporaryDirectory() as tmpdir:
                tmp_path = Path(tmpdir)
                csv_path = self._write_csv(
                    [
                        ["EvaluatorA", "Entity1", "true"],
                        ["EvaluatorA", "Entity1", "true"],
                    ],
                    tmp_path,
                )
                votes = load_votes(csv_path)
                assessments = analyse_collusion(
                    votes, min_unique_evaluators=2, max_single_share=0.6
                )
                flagged = [a for a in assessments if a.alerts]

                self.assertEqual(1, len(flagged))
                self.assertIn("insufficient_unique", flagged[0].alerts[0])

    def test_flags_dominant_share(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            csv_path = self._write_csv(
                [
                    ["EvaluatorA", "Entity1", "true"],
                    ["EvaluatorA", "Entity1", "false"],
                    ["EvaluatorA", "Entity1", "true"],
                    ["EvaluatorB", "Entity1", "true"],
                ],
                tmp_path,
            )
            votes = load_votes(csv_path)
            assessments = analyse_collusion(
                votes, min_unique_evaluators=2, max_single_share=0.6
            )
            flagged = [a for a in assessments if a.alerts]

            self.assertEqual(1, len(flagged))
            self.assertTrue(
                any("dominant_share" in reason for reason in flagged[0].alerts)
            )

    def test_passes_when_thresholds_met(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            csv_path = self._write_csv(
                [
                    ["EvaluatorA", "Entity1", "true"],
                    ["EvaluatorB", "Entity1", "true"],
                    ["EvaluatorC", "Entity1", "false"],
                ],
                tmp_path,
            )
            votes = load_votes(csv_path)
            assessments = analyse_collusion(
                votes, min_unique_evaluators=2, max_single_share=0.6
            )
            flagged = [a for a in assessments if a.alerts]

            self.assertFalse(flagged)


if __name__ == "__main__":
    unittest.main()
