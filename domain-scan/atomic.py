import threading

class SafeFileAppender:
    def __init__(self, filename):
        self.filename = filename
        self.lock = threading.Lock()

    def append(self, content):
        with self.lock:
            with open(self.filename, 'a') as file:
                file.write(content)