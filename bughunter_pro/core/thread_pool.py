"""
BugHunter Pro - Thread Pool Manager
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable, List, Any, Optional
import logging

logger = logging.getLogger("bughunter")


class ThreadPoolManager:
    """Manages concurrent task execution with a thread pool."""

    def __init__(self, max_workers: int = 20):
        self.max_workers = max_workers

    def run(
        self,
        func: Callable,
        items: Iterable,
        callback: Optional[Callable] = None,
        description: str = "tasks",
    ) -> List[Any]:
        """
        Execute `func` on each item in `items` using a thread pool.
        Returns a list of non-None results.
        """
        results = []
        items_list = list(items)
        total = len(items_list)
        completed = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_item = {
                executor.submit(func, item): item for item in items_list
            }

            for future in as_completed(future_to_item):
                completed += 1
                try:
                    result = future.result()
                    if result is not None:
                        results.append(result)
                        if callback:
                            callback(result)
                except Exception as exc:
                    item = future_to_item[future]
                    logger.debug(
                        f"Exception during {description} for {item}: {exc}"
                    )

                if completed % 50 == 0 or completed == total:
                    logger.debug(
                        f"Progress [{description}]: {completed}/{total}"
                    )

        return results