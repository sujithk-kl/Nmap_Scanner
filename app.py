from flask import Flask, render_template, request
import nmap

app = Flask(__name__)
scanner = nmap.PortScanner()

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
            for host in scanner.all_hosts():
                results[host] = {
                    "state": scanner[host].state(),
                    "protocols": {}
                }
                for proto in scanner[host].all_protocols():
                    ports = scanner[host][proto].keys()
                    results[host]["protocols"][proto] = {
                        port: scanner[host][proto][port]['state']
                        for port in ports
                    }
        except Exception as e:
            results["error"] = str(e)

    return render_template("index.html", results=results)

if __name__ == "__main__":
    app.run(debug=True)
