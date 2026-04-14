import socket
import threading
from protocol import SecureSocket
from gui import VPNClientApp

ADDR = ("79.177.161.218", 8000)

def connection_worker(app):
    """Handles network connection in the background so the GUI doesn't freeze."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(ADDR)
        secure = SecureSocket(sock)
        secure.client_handshake()
        
        # Link socket to GUI and unlock it
        app.secure = secure
        app.after(0, app.connection_successful)
        
        # Start listening for messages
        while True:
            try:
                msg = secure.recv_json()
                app.handle_incoming(msg)
            except Exception as e:
                print(f"[CLIENT] Disconnected: {e}")
                app.after(0, app.connection_lost)
                break
                
    except Exception as e:
        print(f"[CLIENT] Connection failed: {e}")
        app.after(0, app.connection_lost)

def main():
    # Launch GUI immediately
    app = VPNClientApp()
    
    # Start background thread to connect and listen
    conn_thread = threading.Thread(target=connection_worker, args=(app,), daemon=True)
    conn_thread.start()

    # Run the GUI mainloop
    app.mainloop()

if __name__ == "__main__":
    main()