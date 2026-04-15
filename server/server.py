import socket
import threading
import sqlite3
import os
import bcrypt
from protocol import SecureSocket

HOST = "0.0.0.0"
PORT = 8000
RUNNING = True
DB_FILE = "users.db"

# Thread safety locks
db_lock = threading.Lock()
session_lock = threading.Lock()
server_lock = threading.Lock() # Lock for the VPN servers list

# State tracking
active_sessions = {}   # username -> addr
available_servers = {} # server_name -> {"addr": addr, "display_name": name, "load": string}

#db funcs:
def init_db():
    if not os.path.exists(DB_FILE):
        with db_lock:
            with sqlite3.connect(DB_FILE) as conn:
                c = conn.cursor()
                # Table for end-users
                c.execute("""
                    CREATE TABLE users (
                        username TEXT PRIMARY KEY,
                        password_hash TEXT NOT NULL
                    )
                """)
                # Table for authorized VPN nodes
                c.execute("""
                    CREATE TABLE vpn_servers (
                        server_name TEXT PRIMARY KEY,
                        display_name TEXT NOT NULL
                    )
                """)
                
                # Insert a dummy VPN server for testing
                add_server("node_01", "Israel, Herzliya")

        print("[DB] Database created and initialized with dummy VPN node.")

def add_server(server_name, display_name):
    with db_lock:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("INSERT INTO vpn_servers (server_name, display_name) VALUES (?, ?)", 
                                (f"{server_name}", f"{display_name}"))
            conn.commit()


def add_user(username, password):
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    with db_lock:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT 1 FROM users WHERE username = ?", (username,))
            if c.fetchone():
                return False
            c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed))
            conn.commit()
    return True

def check_user(username, password):
    with db_lock:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
            row = c.fetchone()
    if row:
        stored_hash = row[0].encode('utf-8')
        return bcrypt.checkpw(password.encode('utf-8'), stored_hash)
    return False

def check_vpn_server(server_name):
    with db_lock:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT display_name FROM vpn_servers WHERE server_name = ?", (server_name,))
            row = c.fetchone()
    if row: 
        return True, row[0]
    return False, None

#logic funcs:
def login(data, addr):
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return {"cmd": "EROR", "msg": "Missing username or password"}

    with session_lock:
        if username in active_sessions:
            return {"cmd": "EROR", "msg": "User already logged in"}

    if check_user(username, password):
        with session_lock:
            active_sessions[username] = addr
        return {"cmd": "CNFM", "action": "LGIN", "username": username}
    else:
        return {"cmd": "EROR", "msg": "Invalid credentials"}

def register(data, addr):
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return {"cmd": "EROR", "msg": "Missing username or password"}
        
    if add_user(username, password):
        return {"cmd": "CNFM", "action": "REGI"}
    return {"cmd": "EROR", "msg": "Username already exists"}

def logoff(username, addr):
    with session_lock:
        if username and username in active_sessions:
            del active_sessions[username]
            return {"cmd": "CNFM", "action": "LOGF"}
    return {"cmd": "EROR", "msg": "Logoff failed"}

def vpn_server_login(data, addr):
    server_name = data.get("server_name")
    vpn_port = data.get("port", 50505) 
    #extract ip from json, if not there use addr of the connection
    client_ip = data.get("host", addr[0])                

    if not server_name:
         return {"cmd": "EROR", "msg": "Missing server name"}
         
    is_valid, display_name = check_vpn_server(server_name)
    if is_valid:
        with server_lock:
            available_servers[server_name] = {
                "host": client_ip,            
                "port": vpn_port,             
                "display_name": display_name,
                "load": "12%"                 
            }
        print(f"[BROKER] VPN Node '{display_name}' connected, advertising {client_ip}:{vpn_port}")
        return {"cmd": "CNFM", "action": "SLGN"}
    return {"cmd": "EROR", "msg": "Unknown VPN server"}

def get_server_list():
    with server_lock:
        server_list = [
            {
                "name": s_info["display_name"], 
                "host": s_info["host"],     # Send the IP to the GUI
                "port": s_info["port"],     # Send the Port to the GUI
                "load": s_info["load"]
            }
            for s_name, s_info in available_servers.items()
        ]
    return {"cmd": "SRVS", "servers": server_list}

#cmds:
def handle_lgin(data, addr, user, vpn_node):
    resp = login(data, addr)
    new_user = data.get("username") if resp.get("cmd") == "CNFM" else user
    return resp, new_user, vpn_node

def handle_regi(data, addr, user, vpn_node):
    return register(data, addr), user, vpn_node

def handle_logf(data, addr, user, vpn_node):
    resp = logoff(user, addr)
    new_user = None if resp.get("cmd") == "CNFM" else user
    return resp, new_user, vpn_node

def handle_slgn(data, addr, user, vpn_node):
    resp = vpn_server_login(data, addr)
    new_node = data.get("server_name") if resp.get("cmd") == "CNFM" else vpn_node
    return resp, user, new_node

def handle_list(data, addr, user, vpn_node):
    return get_server_list(), user, vpn_node

def handle_unknown(data, addr, user, vpn_node):
    return {"cmd": "EROR", "msg": "Unknown command"}, user, vpn_node

COMMANDS = {
    "LGIN": handle_lgin,
    "REGI": handle_regi,
    "LOGF": handle_logf,
    "SLGN": handle_slgn,
    "LIST": handle_list
}

#data transfer:
def handle_client(conn, addr):
    print(f"[SERVER] Connection established from {addr}")
    try:
        secure = SecureSocket(conn)
        secure.server_handshake()
    except Exception as e:
        print(f"[SERVER] Handshake failed with {addr}: {e}")
        conn.close()
        return

    current_user = None
    current_vpn_server = None

    while True:
        try:
            data = secure.recv_json()
        except Exception as e:
            print(f"[SERVER] Disconnected from {addr}")
            with session_lock:
                if current_user in active_sessions:
                    del active_sessions[current_user]
            with server_lock:
                if current_vpn_server in available_servers:
                    del available_servers[current_vpn_server]
                    print(f"[BROKER] VPN Node '{current_vpn_server}' went offline.")
            return

        cmd = data.get("cmd")
        response, current_user, current_vpn_server = COMMANDS.get(cmd, handle_unknown)(data, addr, current_user, current_vpn_server)

        try:
            print(response)
            secure.send_json(response)
        except Exception:
            break

#listen
def start_server():
    init_db()
    server.listen(5)
    print(f"[BROKER] Listening on ({HOST}, {PORT})")
    threads = []
    while RUNNING:
        try:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
            threads.append(t)
        except KeyboardInterrupt:
            print("\n[SERVER] Shutting down...")
            break

if __name__ == "__main__":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    start_server()