"""Quiz module runner that reuses the latest generated quiz report when available."""

# from __future__ import annotations

import shutil
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from src.runners.base_runner import BaseRunner


class Runner(BaseRunner):
	"""Return the most recent quiz report if it is still fresh enough to reuse."""

	REPORT_MAX_AGE = timedelta(days=7)

	def run(self, output_dir: Path, module_dir: Path) -> tuple[bool, list[Path]]:
		"""Copy the most recent quiz report into the output directory when recent."""

		reports_dir = module_dir / "scan-assess-quiz" / "reports"
		latest_report = self._find_latest_report(reports_dir)
		if latest_report is None:
			print(
				"quiz module: no recent report available; quiz must be run again",
				file=sys.stderr,
			)
			return False, []

		report_mtime = datetime.fromtimestamp(latest_report.stat().st_mtime, tz=UTC)
		if datetime.now(UTC) - report_mtime > self.REPORT_MAX_AGE:
			print(
				f"quiz module: latest report is older than {self.REPORT_MAX_AGE.days} days; quiz must be run again",
				file=sys.stderr,
			)
			return False, []

		copied_report = output_dir / latest_report.name
		shutil.copy2(latest_report, copied_report)
		copied_files = [copied_report]
		json_report = latest_report.with_suffix(".json")
		if json_report.exists():
			copied_json = output_dir / json_report.name
			shutil.copy2(json_report, copied_json)
			copied_files.append(copied_json)
		return True, copied_files

	def _find_latest_report(self, reports_dir: Path) -> Path | None:
		"""Return the newest markdown report in the quiz reports directory."""

		if not reports_dir.exists():
			return None

		report_files = [
			path
			for path in reports_dir.iterdir()
			if path.is_file() and path.suffix.lower() == ".md"
		]
		if not report_files:
			return None

		return max(report_files, key=lambda path: path.stat().st_mtime)
