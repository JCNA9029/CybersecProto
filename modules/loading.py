# loading.py — Spinner for CLI; silent single-line status for GUI (captured stdout)
import sys
import time
import threading
import itertools

class Spinner:
    def __init__(self, message="Loading..."):
        self.message = message
        self.spinner_cycle = itertools.cycle(['|', '/', '-', '\\'])
        self.running = False
        self.thread = None
        # Detect GUI mode: stdout has been replaced by OutputCapture (no isatty)
        self._gui_mode = not hasattr(sys.stdout, 'isatty') or not sys.stdout.isatty()

    def _spin(self):
        while self.running:
            sys.stdout.write(f"\r{self.message} {next(self.spinner_cycle)}")
            sys.stdout.flush()
            time.sleep(0.1)
            sys.stdout.write('\b' * (len(self.message) + 2))

    def start(self):
        """Starts the spinner animation in a background thread."""
        if self._gui_mode:
            # GUI: print once, no animation loop
            print(self.message)
            return
        self.running = True
        self.thread = threading.Thread(target=self._spin, daemon=True)
        self.thread.start()

    def stop(self):
        """Stops the spinner animation and clears the line."""
        if self._gui_mode:
            return
        self.running = False
        if self.thread:
            self.thread.join()
        sys.stdout.write('\r' + ' ' * (len(self.message) + 2) + '\r')
        sys.stdout.flush()
