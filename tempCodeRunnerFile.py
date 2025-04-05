from flask import Flask, render_template, request
from flask_mysqldb import MySQL  # Import MySQL class
import socket
import time

app = Flask(__name__)

# MySQL configuration
app.config['MYSQL_HOST'] = 'localhost'  # Replace with your hostname
app.config['MYSQL_USER'] = 'root'  # Replace with your username
app.config['MYSQL_PASSWORD'] = ''  # Replace with your password
app.config['MYSQL_DB'] = 'flask_db'  # Replace with your database name

# Initialize MySQL connection
mysql = MySQL(app)

def is_valid_ip(ip):
    """Check if the input is a valid IP address."""
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        return False

def scan_ports(target, start_port, end_port):
    """Scan ports on the specified target (IP or domain) and return open ports."""
    open_ports = []
    port_mapping = {
        1: "TCPMUX",
        5: "RJE",
        7: "Echo",
        9: "Discard",
        11: "SYSTAT",
        13: "Daytime",
        17: "Quote of the Day",
        19: "Chargen",
        20: "FTP Data Transfer",
        21: "FTP Control",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        80: "HTTP",
        443: "HTTPS",
    }

    try:
        ip = socket.gethostbyname(target) if not is_valid_ip(target) else target
    except socket.gaierror:
        return "Invalid domain name or IP address."

    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(f"Port {port} ({port_mapping.get(port, 'Unknown Service')}) is open.")

    return "\n".join(open_ports) if open_ports else "No open ports found."

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form['target']
    start_port = int(request.form['start_port'])
    end_port = int(request.form['end_port'])

    start_time = time.time()  # Start timing
    results = scan_ports(target, start_port, end_port)
    duration = time.time() - start_time  # Calculate duration

    # Save scan results to the database
    try:
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO scan_results (target, start_port, end_port, results) VALUES (%s, %s, %s, %s)", (target, start_port, end_port, results))
        mysql.connection.commit()
        cur.close()
    except Exception as e:
        print(f"Error saving scan results to database: {e}")

    return render_template('results.html', results=results, duration=duration)

if __name__ == '__main__':
    app.run(debug=True)