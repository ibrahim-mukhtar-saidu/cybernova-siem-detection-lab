def parse_authentication_logs(log_file):

    events = []

    with open(log_file, "r") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            parts = line.split()

            timestamp = f"{parts[0]} {parts[1]}"
            event_type = parts[2]
            user = parts[3].split("=")[1]
            ip = parts[4].split("=")[1]

            events.append({
                "timestamp": timestamp,
                "event_type": event_type,
                "user": user,
                "ip": ip
            })

    return events
