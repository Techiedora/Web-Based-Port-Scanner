from flask import Flask, render_template, request, flash
from flask_sqlalchemy import SQLAlchemy
import socket
import time
from datetime import datetime
import concurrent.futures

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/flask_db'  # Updated DB URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'  # Important: Set a secret key!

# Database
db = SQLAlchemy(app)

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(80), nullable=False)
    start_port = db.Column(db.Integer, nullable=False)
    end_port = db.Column(db.Integer, nullable=False)
    results = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

# Port Mapping (Extended)
port_mapping = {
    1: "TCPMUX", 5: "RJE", 7: "Echo", 9: "Discard", 11: "SYSTAT", 13: "Daytime",
    17: "Quote of the Day", 19: "Chargen", 20: "FTP Data Transfer", 21: "FTP Control",
    22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP Server",
    68: "DHCP Client", 69: "TFTP", 80: "HTTP", 110: "POP3",
    143: "IMAP", 161: "SNMP", 162: "SNMP Trap",
    443: "HTTPS", 465: "SMTPS", 587: "SMTP (Submission)",
    993: "IMAPS", 995: "POP3S",
    3306: "MySQL",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP (Alternate)",
    8443: "HTTPS (Alternate)",
    # Additional well-known ports:
    3389: "RDP",
    8081: "HTTP (Alternate)",
    8888: "HTTP (Alternate)",
}

def is_valid_ip(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        return False

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)  # Reduced timeout for faster scanning
            result = s.connect_ex((ip, port))
            if result == 0:
                return f"Port {port} ({port_mapping.get(port, 'Unknown Service')}) is open."
            return None
    except Exception as e:
        print(f"Error scanning port {port}: {e}")
        return None

def scan_ports(target, start_port, end_port):
    try:
        ip = socket.gethostbyname(target) if not is_valid_ip(target) else target
    except socket.gaierror:
        return "Invalid domain name or IP address."

    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in range(start_port, end_port + 1)]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    return "\n".join(open_ports) if open_ports else "No open ports found."

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form['target']
    start_port = int(request.form['start_port'])
    end_port = int(request.form['end_port'])

    start_time = time.time()
    results = scan_ports(target, start_port, end_port)
    duration = time.time() - start_time

    # Database interaction (save results)
    new_result = ScanResult(target=target, start_port=start_port, end_port=end_port, results=results)

    try:
        db.session.add(new_result)
        db.session.commit()
        flash("Scan results saved successfully!", "success")
    except Exception as e:
        db.session.rollback()
        print(f"Error saving to database: {e}")
        flash(f"Error saving scan results: {e}", "danger")
    finally:
        db.session.close()

    open_ports = []

    if isinstance(results, str) and results.startswith("Invalid"):
        error_message = results
    else:
        for line in results.splitlines():
            if line:
                open_ports.append(line)
        error_message = None

    return render_template('results.html',
                           target=target,
                           start_port=start_port,
                           end_port=end_port,
                           open_ports=open_ports,
                           duration=duration,
                           error_message=error_message)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
