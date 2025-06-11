# ==========================================
# ChiomaCore Suite - Dashboard
# For educational and authorized use only
# ==========================================
#
# This dashboard is part of the ChiomaCore Suite.
# Use only on systems you own or have explicit permission to test.
# Unauthorized use is strictly prohibited.
#
# For support, visit: https://github.com/chiomacore
# ==========================================

from flask import Flask, render_template_string, redirect, url_for, flash
import subprocess
import webbrowser

app = Flask(__name__)
app.secret_key = "chiomacore_secret"

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>ChiomaCore Suite Dashboard</title>
    <style>
        body { background: #23272A; color: #fff; font-family: Arial; }
        .container { width: 420px; margin: 40px auto; background: #2C2F33; padding: 30px; border-radius: 10px; }
        h1 { color: #43FF64; }
        h3 { color: #7289DA; }
        button, a.button {
            background: #7289DA; color: #fff; border: none; padding: 12px 0; width: 100%; margin: 8px 0;
            font-size: 16px; border-radius: 5px; cursor: pointer; text-decoration: none; display: block;
        }
        .about, .footer { color: #888; font-size: 12px; margin-top: 10px; }
        .netinfo { background: #FFD700; color: #23272A; }
        .github { background: #333; color: #fff; }
        .exit { background: #FF4343; }
        pre { background: #18191C; color: #FFD700; padding: 10px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>ChiomaCore Suite</h1>
        <h3>Network Security Tools</h3>
        <form method="post" action="/run_tool">
            <button name="tool" value="network_scanner">Network Scanner</button>
            <button name="tool" value="arp_spoofer">ARP Spoofer</button>
            <button name="tool" value="dns_spoofer">DNS Spoofer</button>
            <button name="tool" value="packet_sniffer">Packet Sniffer</button>
            <button name="tool" value="credentials_extractor">Credentials Extractor</button>
        </form>
        <form method="get" action="/network_info">
            <button class="netinfo">Show Network Info</button>
        </form>
        <a href="https://github.com/chiomacore" target="_blank" class="button github">GitHub Support</a>
        <form method="get" action="/about">
            <button class="about">About</button>
        </form>
        <form method="get" action="/exit">
            <button class="exit">Exit</button>
        </form>
        {% if netinfo %}
            <h4>ipconfig /all</h4>
            <pre>{{ netinfo }}</pre>
        {% endif %}
        {% with messages = get_flashed_messages() %}
          {% if messages %}
            <ul>
            {% for message in messages %}
              <li style="color:#FFD700;">{{ message }}</li>
            {% endfor %}
            </ul>
          {% endif %}
        {% endwith %}
        <div class="footer">For authorized use only | github.com/chiomacore</div>
    </div>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def dashboard():
    return render_template_string(TEMPLATE, netinfo=None)

@app.route("/run_tool", methods=["POST"])
def run_tool():
    from flask import request
    tool = request.form.get("tool")
    tool_map = {
        "network_scanner": "core/network_scanner.py",
        "arp_spoofer": "core/arp_spoofer.py",
        "dns_spoofer": "core/dns_spoofer.py",
        "packet_sniffer": "core/packet_sniffer.py",
        "credentials_extractor": "core/credentials_extractor.py"
    }
    script = tool_map.get(tool)
    if script:
        try:
            subprocess.Popen(["python", script])
            flash(f"{tool.replace('_', ' ').title()} launched in a new process.")
        except Exception as e:
            flash(f"Error launching {tool}: {e}")
    else:
        flash("Unknown tool selected.")
    return redirect(url_for("dashboard"))

@app.route("/network_info", methods=["GET"])
def network_info():
    try:
        result = subprocess.check_output("ipconfig /all", shell=True, text=True)
        # Show only first 2000 chars for brevity
        result = result[:2000] + ("\n...output truncated..." if len(result) > 2000 else "")
    except Exception as e:
        result = f"Error running ipconfig: {e}"
    return render_template_string(TEMPLATE, netinfo=result)

@app.route("/about", methods=["GET"])
def about():
    flash("ChiomaCore Suite: A collection of network security tools for educational and authorized use only. https://github.com/chiomacore")
    return redirect(url_for("dashboard"))

@app.route("/exit", methods=["GET"])
def exit_app():
    flash("To exit, simply close this browser tab and stop the Flask server in your terminal.")
    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    app.run(debug=True)