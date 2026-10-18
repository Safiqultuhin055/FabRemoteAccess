"""Run blocking calls (HTTP) off the UI thread and deliver results back on it."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal

_pending: set = set()   # keep signal objects alive until their task reports back


class _Signals(QObject):
    succeeded = Signal(object)
    failed = Signal(object)


class _Task(QRunnable):
    def __init__(self, fn: Callable[[], object], signals: _Signals):
        super().__init__()
        self._fn = fn
        self._signals = signals

    def run(self) -> None:
        try:
            result = self._fn()
        except Exception as exc:  # noqa: BLE001 - handed to the UI callback
            self._signals.failed.emit(exc)
        else:
            self._signals.succeeded.emit(result)


def run_async(fn: Callable[[], object], on_success: Callable[[object], None],
              on_error: Callable[[Exception], None]) -> None:
    signals = _Signals()   # created on the UI thread, so callbacks run there
    _pending.add(signals)

    def done(handler):
        def slot(value):
            _pending.discard(signals)
            handler(value)
        return slot

    signals.succeeded.connect(done(on_success))
    signals.failed.connect(done(on_error))
    QThreadPool.globalInstance().start(_Task(fn, signals))
