import re


class LogPreprocessor:

    def parse_log_line(self, line: str) -> dict | None:
        line = line.strip()
        if not line:
            return None

        pattern = r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s+(\w+)\s+(.+)"
        match = re.match(pattern, line)

        if match:
            timestamp, level, message = match.groups()
        else:
            timestamp, level, message = "unknown", "INFO", line

        ips   = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", message)
        users = re.findall(r"[Uu]ser\s+(\w+)", message)

        return {
            "timestamp":   timestamp,
            "level":       level,
            "message":     message.lower(),
            "ip_addresses": ips,
            "usernames":   users,
            "raw":         line,
        }

    def build_sequences(self, logs: list, window_size: int = 5) -> list:
        sequences = []
        for i in range(max(1, len(logs) - window_size + 1)):
            window = logs[i : i + window_size]
            combined = " [SEP] ".join(log["message"] for log in window)
            sequences.append({
                "text":        combined,
                "logs":        window,
                "start_index": i,
            })
        return sequences

    def process_text(self, raw: str) -> list:
        parsed = []
        for line in raw.strip().splitlines():
            r = self.parse_log_line(line)
            if r:
                parsed.append(r)
        return parsed