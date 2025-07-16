from flask import Flask, render_template, request
import nmap

app = Flask(__name__)
scanner = nmap.PortScanner()

# Global variable to store the latest scan results
latest_scan = {
    'results': {},
    'stats': {'open': 0, 'closed': 0, 'filtered': 0, 'scans': 0}
}

@app.route("/", methods=["GET", "POST"])
def index():
    results = {}
    if request.method == "POST":
        ip = request.form.get("ip")
        scan_type = request.form.get("scan_type")
        scan_args = {
            "1": "-v -sS",
            "2": "-v -sU",
            "3": "-v -sS -sV -sC -A -O"
        }.get(scan_type, "-v -sS")

        try:
            scanner.scan(ip, "1-1024", scan_args)
            open_ports = closed_ports = filtered_ports = 0
            for host in scanner.all_hosts():
                results[host] = {
                    "state": scanner[host].state(),
                    "protocols": {}
                }
                for proto in scanner[host].all_protocols():
                    ports = scanner[host][proto].keys()
                    port_states = {}
                    for port in ports:
                        state = scanner[host][proto][port]['state']
                        port_states[port] = state
                        if state == 'open':
                            open_ports += 1
                        elif state == 'closed':
                            closed_ports += 1
                        elif state == 'filtered':
                            filtered_ports += 1
                    results[host]["protocols"][proto] = port_states
            # Store latest scan and stats
            latest_scan['results'] = results
            latest_scan['stats'] = {
                'open': open_ports,
                'closed': closed_ports,
                'filtered': filtered_ports,
                'scans': latest_scan['stats']['scans'] + 1
            }
        except Exception as e:
            results["error"] = str(e)
    return render_template("index.html", results=results)

@app.route("/dashboard")
def dashboard():
    results = latest_scan['results']
    stats = latest_scan['stats']
    return render_template("dashboard.html", results=results, stats=stats)

if __name__ == "__main__":
    app.run(debug=True)
