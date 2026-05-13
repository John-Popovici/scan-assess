"""Abstract base class for all module runners."""

from abc import ABC, abstractmethod
from pathlib import Path


class BaseRunner(ABC):
    """
    Abstract base class that defines the interface for all module runners.
    
    Each module must implement a Runner class that inherits from BaseRunner
    and implements the run() method.
    """

    @abstractmethod
    def run(self, output_dir: Path, module_dir: Path) -> tuple[bool, list[Path]]:
        """
        Execute the module and generate output files.

        Args:
            output_dir: Directory where the module should write its output files.
            module_dir: Directory containing the module's source code and data.

        Returns:
            A tuple containing a boolean indicating success
            and a list of Path objectspointing to all generated JSON files.
            Only files with .json extension should be included in the returned list.
        """
        pass
