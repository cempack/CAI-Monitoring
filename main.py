import redfish
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
import threading
import time
from datetime import datetime

# Initialize Flask application
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///servers.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'PWCQAF-N*h92NbEJ!Prn'

# Initialize SQLAlchemy
db = SQLAlchemy(app)


# Define Server model for SQLite
class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ilo_ip = db.Column(db.String(100), unique=True, nullable=False)
    ilo_username = db.Column(db.String(100), nullable=False)
    ilo_password = db.Column(db.String(100), nullable=False)
    enterprise_name = db.Column(db.String(100), nullable=False)
    server_name = db.Column(db.String(100))
    product_name = db.Column(db.String(100))
    serial_number = db.Column(db.String(100))
    system_health = db.Column(db.String(50))
    bios_version = db.Column(db.String(100))
    memory = db.Column(db.Float)
    fans_health = db.Column(db.String(100))
    processors_count = db.Column(db.Integer)
    network_interfaces_count = db.Column(db.Integer)
    power_status = db.Column(db.String(50))
    online = db.Column(db.Boolean, default=False)
    last_updated = db.Column(db.DateTime)


# Define Credentials model for SQLite
class Credentials(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)


# Function to connect and fetch data from Redfish API
def fetch_data(client, uri):
    try:
        response = client.get(uri)
        return response.dict
    except Exception as e:
        app.logger.error(f"Error fetching data from {uri}: {str(e)}")
        return {}


# Function to fetch all server information
def fetch_all_server_info(client):
    systems_uri = "/redfish/v1/Systems/1"
    basic_info = fetch_data(client, systems_uri)

    server_name = basic_info.get("HostName", "")
    product_name = basic_info.get("Model", "")
    serial_number = basic_info.get("SerialNumber", "")
    system_health = basic_info.get("Status", {}).get("Health", "")

    bios_version = basic_info.get("BiosVersion", "")
    memory = basic_info.get("MemorySummary", {}).get("TotalSystemMemoryGiB", "")
    power_status = basic_info.get("PowerState", "")

    fan_health_uri = "/redfish/v1/Chassis/1/Thermal"
    fan_health_info = fetch_data(client, fan_health_uri)
    fans = fan_health_info.get("Fans", [])
    not_ok_fans = [fan["FanName"] for fan in fans if fan["Status"]["Health"] != "OK"]
    fans_health = "OK" if not not_ok_fans else "Not OK: " + ", ".join(not_ok_fans)

    processors_uri = "/redfish/v1/Systems/1/Processors"
    processors_info = fetch_data(client, processors_uri)
    processors_count = len(processors_info.get("Members", [])) if processors_info else "Not available"

    network_interfaces_uri = "/redfish/v1/Systems/1/EthernetInterfaces"
    network_interfaces_info = fetch_data(client, network_interfaces_uri)
    network_interfaces_count = len(
        network_interfaces_info.get("Members", [])) if network_interfaces_info else "Not available"

    return {
        "server_name": server_name,
        "product_name": product_name,
        "serial_number": serial_number,
        "system_health": system_health,
        "bios_version": bios_version,
        "memory": memory,
        "fans_health": fans_health,
        "processors_count": processors_count,
        "network_interfaces_count": network_interfaces_count,
        "power_status": power_status
    }


# Background task to fetch and store data
def background_task():
    with app.app_context():
        while True:
            try:
                servers = Server.query.all()
                for server in servers:
                    client = None
                    try:
                        client = redfish.redfish_client(base_url=f"https://{server.ilo_ip}",
                                                        username=server.ilo_username,
                                                        password=server.ilo_password)
                        client.login()
                        server.online = True  # Server is online if login succeeds
                        # Fetch all server information and update in the database
                        server_info = fetch_all_server_info(client)
                        update_server_data(server.id, server_info)
                    except Exception as e:
                        server.online = False  # Server is offline if login fails or any exception occurs
                        app.logger.error(f"Error updating server {server.ilo_ip}: {str(e)}")
                    finally:
                        if client:
                            client.logout()
                    db.session.commit()
                    time.sleep(3)
            except Exception as e:
                app.logger.error(f"Background task error: {str(e)}")
                db.session.rollback()
                time.sleep(60)  # Sleep for a minute before retrying


# Function to update server data in the database
def update_server_data(server_id, data):
    try:
        server = db.session.get(Server, server_id)
        if server:
            server.server_name = data.get("server_name")
            server.product_name = data.get("product_name")
            server.serial_number = data.get("serial_number")
            server.system_health = data.get("system_health")
            server.bios_version = data.get("bios_version")
            server.memory = data.get("memory")
            server.fans_health = data.get("fans_health")
            server.processors_count = data.get("processors_count")
            server.network_interfaces_count = data.get("network_interfaces_count")
            server.power_status = data.get("power_status")
            server.last_updated = datetime.now()  # Update last updated time
            db.session.commit()
    except SQLAlchemyError as e:
        app.logger.error(f"Error updating server data: {str(e)}")
        db.session.rollback()


def login_required(f):
    def wrap(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    wrap.__name__ = f.__name__
    return wrap


@app.route('/login', methods=['GET', 'POST'])
def login():
    credentials = Credentials.query.first()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if credentials and username == credentials.username and password == credentials.password:
            session['logged_in'] = True
            return redirect(url_for('render_server_info'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))


@app.route('/add_server', methods=['POST'])
@login_required
def add_server():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400

        ilo_ip = data.get('ilo_ip')
        ilo_username = data.get('ilo_username')
        ilo_password = data.get('ilo_password')
        enterprise_name = data.get('enterprise_name')

        if not all([ilo_ip, ilo_username, ilo_password, enterprise_name]):
            return jsonify({'error': 'Missing required fields'}), 400

        client = None
        try:
            client = redfish.redfish_client(base_url=f"https://{ilo_ip}",
                                            username=ilo_username,
                                            password=ilo_password)
            client.login()

            # If connection is successful, fetch all server information
            server_info = fetch_all_server_info(client)

            # Attempt to add the server to the database
            try:
                new_server = Server(ilo_ip=ilo_ip,
                                    ilo_username=ilo_username,
                                    ilo_password=ilo_password,
                                    enterprise_name=enterprise_name,
                                    server_name=server_info.get("server_name"),
                                    product_name=server_info.get("product_name"),
                                    serial_number=server_info.get("serial_number"),
                                    system_health=server_info.get("system_health"),
                                    bios_version=server_info.get("bios_version"),
                                    memory=server_info.get("memory"),
                                    fans_health=server_info.get("fans_health"),
                                    processors_count=server_info.get("processors_count"),
                                    network_interfaces_count=server_info.get("network_interfaces_count"),
                                    power_status=server_info.get("power_status"),
                                    online=True)

                db.session.add(new_server)
                db.session.commit()
                return jsonify({'message': 'Server added successfully'}), 201
            except IntegrityError:
                db.session.rollback()
                return jsonify({'error': 'Server with this iLO IP already exists'}), 400
        except Exception as e:
            return jsonify({'error': str(e)}), 400
        finally:
            if client:
                client.logout()

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400


@app.route('/delete_server/<int:server_id>', methods=['DELETE'])
@login_required
def delete_server(server_id):
    try:
        server = db.session.get(Server, server_id)
        if server:
            db.session.delete(server)
            db.session.commit()
            return jsonify({'message': 'Server deleted successfully'}), 200
        else:
            return jsonify({'message': 'Server not found'}), 404
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400


@app.route('/edit_server/<int:server_id>', methods=['GET', 'POST'])
@login_required
def edit_server(server_id):
    server = db.session.get(Server, server_id)
    if not server:
        return jsonify({'error': 'Serveur introuvable'}), 404

    if request.method == 'POST':
        try:
            data = request.get_json()
            ilo_ip = data.get('ilo_ip')
            ilo_username = data.get('ilo_username')
            ilo_password = data.get('ilo_password')
            enterprise_name = data.get('enterprise_name')

            if not all([ilo_ip, ilo_username, ilo_password, enterprise_name]):
                return jsonify({'error': 'Missing required fields'}), 400

            # Check if any details other than enterprise_name are changed
            if (ilo_ip != server.ilo_ip or
                    ilo_username != server.ilo_username or
                    ilo_password != server.ilo_password):

                # Validate the new server details by attempting to connect
                client = None
                try:
                    client = redfish.redfish_client(base_url=f"https://{ilo_ip}",
                                                    username=ilo_username,
                                                    password=ilo_password)
                    client.login()
                except Exception as e:
                    return jsonify({'error': f"La connexion au serveur a échoué: {str(e)}"}), 400
                finally:
                    if client:
                        client.logout()

            # Update server details
            server.ilo_ip = ilo_ip
            server.ilo_username = ilo_username
            server.ilo_password = ilo_password
            server.enterprise_name = enterprise_name

            # Commit changes
            db.session.commit()
            return jsonify({'message': 'Les détails du serveur ont été mis a jour avec succés.'}), 200

        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 400

    return render_template('edit.html', server=server)


@app.route('/edit_credentials', methods=['GET', 'POST'])
@login_required
def edit_credentials():
    credentials = Credentials.query.first()
    if request.method == 'POST':
        new_username = request.form['username']
        new_password = request.form['password']

        if not credentials:
            credentials = Credentials(username=new_username, password=new_password)
            db.session.add(credentials)
        else:
            credentials.username = new_username
            credentials.password = new_password

        db.session.commit()
        return redirect(url_for('edit_credentials'))

    return render_template('edit_credentials.html', credentials=credentials)


@app.route('/add', methods=['GET'])
@login_required
def render_add_server_form():
    return render_template('add.html')


@app.route('/delete/<int:server_id>', methods=['GET'])
@login_required
def render_delete_server_form(server_id):
    server = db.session.get(Server, server_id)
    if server:
        return render_template('delete.html', server=server)
    else:
        return jsonify({'error': 'Server not found'}), 404


@app.route('/enterprises', methods=['GET'])
@login_required
def list_enterprises():
    enterprises = db.session.query(Server.enterprise_name, db.func.count(Server.id)).group_by(
        Server.enterprise_name).all()
    enterprise_data = [{'name': enterprise[0], 'count': enterprise[1]} for enterprise in enterprises]
    return render_template('enterprises.html', enterprises=enterprise_data)


@app.route('/enterprise/<name>', methods=['GET'])
@login_required
def view_enterprise(name):
    servers = Server.query.filter_by(enterprise_name=name).all()
    return render_template('enterprise.html', enterprise_name=name, servers=servers)


@app.route('/server/<int:server_id>', methods=['GET'])
@login_required
def render_server_details(server_id):
    server = db.session.get(Server, server_id)
    if server:
        return render_template('server_details.html', server=server)
    else:
        return jsonify({'error': 'Server not found'}), 404


@app.route('/', methods=['GET'])
@login_required
def render_server_info():
    servers = Server.query.all()
    return render_template('index.html', servers=servers)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    # Start background task
    bg_task = threading.Thread(target=background_task)
    bg_task.start()

    app.run(debug=True)
