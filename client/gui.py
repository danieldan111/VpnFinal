import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk
import subprocess
import sys
import threading

# --- UI Setup ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# --- Built-In Debug Console ---
class DebugConsole(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("VPN Live Logs")
        self.geometry("700x450")
        
        # Make the window pop to the front
        self.attributes("-topmost", True)
        
        self.textbox = ctk.CTkTextbox(self, font=("Courier", 14), fg_color="black", text_color="#00FF00")
        self.textbox.pack(fill="both", expand=True, padx=10, pady=10)
        self.textbox.configure(state="disabled")

    def write_log(self, text):
        self.textbox.configure(state="normal")
        self.textbox.insert("end", text)
        self.textbox.see("end")  # Auto-scroll to the bottom
        self.textbox.configure(state="disabled")


class VPNClientApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("VPN Client")
        self.geometry("800x600")
        self.resizable(False, False)
        
        self.secure = None
        self.current_user = None
        self.waiting_response = False
        self.timeout_id = None
        
        # --- Track the VPN subprocess globally ---
        self.active_vpn_process = None
        self.connected_server = None  
        self.debug_window = None
        
        self.current_frame_name = "ConnectingPage"

        self.container = ctk.CTkFrame(self)
        self.container.pack(fill="both", expand=True)

        self.frames = {}
        # Load all pages into the dictionary
        for F in (ConnectingPage, HomePage, LoginPage, RegisterPage, VPNPage, ConnectedPage):
            page_name = F.__name__
            frame = F(parent=self.container, controller=self)
            self.frames[page_name] = frame
            frame.place(relwidth=1, relheight=1)

        self.show_frame("ConnectingPage")

    # ---------------- Frame Navigation ---------------- #
    def show_frame(self, page_name):
        self.current_frame_name = page_name
        frame = self.frames[page_name]
        frame.clear_fields()
        frame.tkraise()

    # ---------------- Network / Timeout Handling ---------------- #
    def connection_successful(self):
        self.show_frame("HomePage")

    def connection_lost(self):
        messagebox.showerror("Network Error", "Lost connection to the broker server.")
        self.destroy()

    def set_waiting(self, is_waiting):
        self.waiting_response = is_waiting
        if is_waiting:
            self.timeout_id = self.after(5000, self.handle_timeout)
        else:
            if self.timeout_id:
                self.after_cancel(self.timeout_id)
                self.timeout_id = None

    def handle_timeout(self):
        self.waiting_response = False
        messagebox.showwarning("Timeout", "The server took too long to respond.")
        self.frames[self.current_frame_name].enable_inputs()

    def handle_incoming(self, data):
        self.after(0, self.process_incoming, data)

    # ---------------- Dictionary Dispatcher ---------------- #
    def handle_login_success(self, data):
        self.current_user = data.get("username", self.current_user)
        self.show_frame("VPNPage")

    def handle_register_success(self, data):
        messagebox.showinfo("Success", "Registration successful!")
        self.show_frame("HomePage")

    def handle_logoff_success(self, data):
        self.current_user = None
        self.show_frame("HomePage")

    def handle_confirm(self, data):
        actions = {
            "LGIN": self.handle_login_success,
            "REGI": self.handle_register_success,
            "LOGF": self.handle_logoff_success
        }
        handler = actions.get(data.get("action"), self.handle_error)
        handler(data)

    def handle_servers_list(self, data):
        if "VPNPage" in self.frames:
            self.frames["VPNPage"].populate_servers(data.get("servers", []))

    def handle_error(self, data):
        error_msg = data.get("msg", "Unknown error or command from server.")
        messagebox.showerror("Error", error_msg)
        self.frames[self.current_frame_name].enable_inputs()

    def process_incoming(self, data):
        """Process JSON server messages using Command Dispatch."""
        self.set_waiting(False)
        commands = {
            "CNFM": self.handle_confirm,
            "SRVS": self.handle_servers_list,
            "EROR": self.handle_error
        }
        cmd = data.get("cmd")
        commands.get(cmd, self.handle_error)(data)

    # ---------------- VPN Subprocess Control ---------------- #
    def start_vpn(self, srv, show_console=False):
        """Launches the VPN client subprocess and captures its output internally."""
        self.stop_vpn(switch_page=False) 
        
        target_ip = srv.get("host", "127.0.0.1")
        target_port = str(srv.get("port", "8000"))
        
        # -u flag forces unbuffered output so we get logs instantly
        print(f"[CLIENT] connecting to vpn server at ({target_ip}, {target_port})")
        cmd = [sys.executable, "-u", "clientVpn.py", target_ip, target_port]
        
        kwargs = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.STDOUT, # Merge errors into standard output
            "text": True,
            "bufsize": 1
        }
        
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

        try:
            self.active_vpn_process = subprocess.Popen(cmd, **kwargs)

            if show_console:
                self.debug_window = DebugConsole(self)

            # Start background thread to read logs without freezing the GUI
            threading.Thread(
                target=self.monitor_vpn_output, 
                args=(self.active_vpn_process, self.debug_window), 
                daemon=True
            ).start()

            # Wait to see if it crashes before switching to ConnectedPage
            self.after(3000, self.verify_vpn_connection, srv, show_console)
            
        except Exception as e:
            messagebox.showerror("Execution Error", f"Failed to execute VPN script:\n{e}")

    def monitor_vpn_output(self, process, debug_window):
        """Reads the subprocess output line by line in real-time."""
        for line in iter(process.stdout.readline, ''):
            if debug_window and debug_window.winfo_exists():
                # Safely tell Tkinter to update the UI from this background thread
                self.after(0, debug_window.write_log, line)
            
            # Also print to your IDE terminal just in case
            print(f"[VPN Client] {line}", end="")
            
        process.stdout.close()

    def verify_vpn_connection(self, srv, show_console):
        """Checks if the subprocess is still running after 1 second."""
        if self.active_vpn_process is None:
            return

        return_code = self.active_vpn_process.poll()

        if return_code is None:
            print("[GUI] VPN Process verified. Switching to Connected dashboard.")
            self.connected_server = srv
            self.show_frame("ConnectedPage")

            self.check_vpn_status()

        else:
            msg = f"The VPN script crashed quickly (Exit Code {return_code})."
            if show_console:
                msg += "\n\nPlease look at the green Debug Console window to see the exact error."
            else:
                msg += "\n\nPlease check 'Show Debug Console' and try again to see why it crashed."
                
            messagebox.showerror("VPN Connection Failed", msg)
            self.active_vpn_process = None
            self.connected_server = None
            
            if "VPNPage" in self.frames:
                self.frames["VPNPage"].fetch_servers()

    def check_vpn_status(self):
        """Continuously checks if the background VPN process died unexpectedly."""
        # If we aren't tracking a process anymore (user clicked disconnect), stop checking.
        if self.active_vpn_process is None:
            return
            
        return_code = self.active_vpn_process.poll()
        
        if return_code is not None:
            # The process died! (Timeout triggered SIGINT, or the server crashed)
            print(f"[GUI] VPN Process terminated unexpectedly (Code {return_code}).")
            
            # Optional: Tell the user what happened
            messagebox.showwarning("VPN Disconnected", "The connection to the VPN server was lost.")
            
            # Your existing stop_vpn method handles the rest (cleaning up and switching to VPNPage)
            self.stop_vpn(switch_page=True)
        else:
            # The process is still running smoothly. Check again in 1000ms (1 second).
            self.after(1000, self.check_vpn_status)

    def stop_vpn(self, switch_page=True):
        """Kills the running VPN client subprocess."""
        if self.active_vpn_process is not None:
            if self.active_vpn_process.poll() is None: 
                self.active_vpn_process.terminate()
                self.active_vpn_process.wait() 
            
            print("[GUI] Terminated VPN connection.")
            self.active_vpn_process = None
            self.connected_server = None
            
        if hasattr(self, 'debug_window') and self.debug_window is not None:
            try:
                self.debug_window.destroy()
            except:
                pass
            self.debug_window = None
            
        if switch_page:
            self.show_frame("VPNPage")


# ---------------- Pages ---------------- #
class BasePage(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

    def clear_fields(self): pass
    def disable_inputs(self): pass
    def enable_inputs(self): pass

class ConnectingPage(BasePage):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        label = ctk.CTkLabel(self, text="Connecting to Broker...", font=("Arial", 28))
        label.pack(expand=True)

class HomePage(BasePage):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        label = ctk.CTkLabel(self, text="VPN Client", font=("Arial", 36))
        label.pack(pady=50)

        btn_login = ctk.CTkButton(self, text="Login", command=lambda: controller.show_frame("LoginPage"), height=50, width=200)
        btn_login.pack(pady=20)
        btn_register = ctk.CTkButton(self, text="Register", command=lambda: controller.show_frame("RegisterPage"), height=50, width=200)
        btn_register.pack(pady=20)

class LoginPage(BasePage):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self.label = ctk.CTkLabel(self, text="Login", font=("Arial", 28))
        self.label.pack(pady=20)

        self.username_entry = ctk.CTkEntry(self, placeholder_text="Username", width=300)
        self.username_entry.pack(pady=10)
        self.password_entry = ctk.CTkEntry(self, placeholder_text="Password", show="*", width=300)
        self.password_entry.pack(pady=10)

        self.submit_btn = ctk.CTkButton(self, text="Login", command=self.submit, height=50, width=200)
        self.submit_btn.pack(pady=20)
        self.home_btn = ctk.CTkButton(self, text="Home", command=self.go_home, height=50, width=150)
        self.home_btn.pack(pady=10)

    def clear_fields(self):
        self.enable_inputs()
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

    def disable_inputs(self):
        self.username_entry.configure(state="disabled")
        self.password_entry.configure(state="disabled")
        self.submit_btn.configure(state="disabled")
        self.home_btn.configure(state="disabled")

    def enable_inputs(self):
        self.username_entry.configure(state="normal")
        self.password_entry.configure(state="normal")
        self.submit_btn.configure(state="normal")
        self.home_btn.configure(state="normal")

    def submit(self):
        if self.controller.waiting_response: return
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
            
        self.disable_inputs()
        self.controller.set_waiting(True)
        payload = {"cmd": "LGIN", "username": username, "password": password}
        self.controller.secure.send_json(payload)

    def go_home(self):
        if not self.controller.waiting_response:
            self.controller.show_frame("HomePage")

class RegisterPage(BasePage):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self.label = ctk.CTkLabel(self, text="Register", font=("Arial", 28))
        self.label.pack(pady=20)

        self.username_entry = ctk.CTkEntry(self, placeholder_text="Username", width=300)
        self.username_entry.pack(pady=10)
        self.password_entry = ctk.CTkEntry(self, placeholder_text="Password", show="*", width=300)
        self.password_entry.pack(pady=10)

        self.submit_btn = ctk.CTkButton(self, text="Register", command=self.submit, height=50, width=200)
        self.submit_btn.pack(pady=20)
        self.home_btn = ctk.CTkButton(self, text="Home", command=self.go_home, height=50, width=150)
        self.home_btn.pack(pady=10)

    def clear_fields(self):
        self.enable_inputs()
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

    def disable_inputs(self):
        self.username_entry.configure(state="disabled")
        self.password_entry.configure(state="disabled")
        self.submit_btn.configure(state="disabled")
        self.home_btn.configure(state="disabled")

    def enable_inputs(self):
        self.username_entry.configure(state="normal")
        self.password_entry.configure(state="normal")
        self.submit_btn.configure(state="normal")
        self.home_btn.configure(state="normal")

    def submit(self):
        if self.controller.waiting_response: return
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
            
        self.disable_inputs()
        self.controller.set_waiting(True)
        payload = {"cmd": "REGI", "username": username, "password": password}
        self.controller.secure.send_json(payload)

    def go_home(self):
        if not self.controller.waiting_response:
            self.controller.show_frame("HomePage")

class VPNPage(BasePage):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        
        # --- Top Navigation Bar ---
        self.nav_bar = ctk.CTkFrame(self, height=50, fg_color="transparent")
        self.nav_bar.pack(fill="x", padx=20, pady=10)

        self.label = ctk.CTkLabel(self.nav_bar, text="Available VPN Servers", font=("Arial", 28, "bold"))
        self.label.pack(side="left")

        self.user_btn = ctk.CTkButton(self.nav_bar, text="👤", width=40, height=40, 
                                      font=("Arial", 20), command=self.toggle_menu)
        self.user_btn.pack(side="right")

        self.refresh_btn = ctk.CTkButton(self.nav_bar, text="🔄 Refresh", width=80, height=40,
                                         font=("Arial", 14), command=self.manual_refresh)
        self.refresh_btn.pack(side="right", padx=10)

        self.show_console_var = ctk.BooleanVar(value=False)
        self.console_checkbox = ctk.CTkCheckBox(self.nav_bar, text="Show Debug Console", 
                                                variable=self.show_console_var)
        self.console_checkbox.pack(side="right", padx=15)

        # --- Dropdown Profile Menu ---
        self.menu_visible = False
        self.menu_frame = ctk.CTkFrame(self, width=150, corner_radius=10, border_width=1, border_color="gray30")
        
        self.user_label = ctk.CTkLabel(self.menu_frame, text="", font=("Arial", 14))
        self.user_label.pack(pady=(10, 5), padx=15)

        self.logoff_btn = ctk.CTkButton(self.menu_frame, text="Log Off", command=self.logoff, 
                                        fg_color="#C62828", hover_color="#B71C1C", width=100)
        self.logoff_btn.pack(pady=(5, 10), padx=15)

        # --- Server List Area ---
        self.server_frame = ctk.CTkScrollableFrame(self)
        self.server_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        self.placeholder = ctk.CTkLabel(self.server_frame, text="Fetching servers...", text_color="gray")
        self.placeholder.pack(pady=20)

    def toggle_menu(self):
        if self.menu_visible:
            self.menu_frame.place_forget()
            self.menu_visible = False
        else:
            self.menu_frame.place(relx=1.0, rely=0.0, x=-20, y=60, anchor="ne")
            self.menu_frame.tkraise()
            self.menu_visible = True

    def clear_fields(self):
        if self.controller.current_user:
            self.user_label.configure(text=f"Logged in as:\n{self.controller.current_user}")
        
        self.logoff_btn.configure(state="normal")
        self.menu_frame.place_forget()
        self.menu_visible = False

        for widget in self.server_frame.winfo_children():
            widget.destroy()
            
        self.placeholder = ctk.CTkLabel(self.server_frame, text="Fetching servers...", text_color="gray")
        self.placeholder.pack(pady=20)

        self.after(1000, self.fetch_servers)

    def manual_refresh(self):
        self.menu_frame.place_forget()
        self.menu_visible = False
        
        for widget in self.server_frame.winfo_children():
            widget.destroy()
            
        self.placeholder = ctk.CTkLabel(self.server_frame, text="Refreshing list...", text_color="gray")
        self.placeholder.pack(pady=20)
        
        self.fetch_servers()

    def fetch_servers(self):
        if self.controller.current_user:
            self.controller.secure.send_json({"cmd": "LIST"})

    def populate_servers(self, servers):
        for widget in self.server_frame.winfo_children():
            widget.destroy()
            
        if not servers:
            empty_label = ctk.CTkLabel(self.server_frame, text="No servers currently online.", text_color="gray")
            empty_label.pack(pady=20)
            return

        for srv in servers:
            row = ctk.CTkFrame(self.server_frame, fg_color=("gray80", "gray15"), corner_radius=8)
            row.pack(fill="x", pady=5, padx=5)
            
            name_lbl = ctk.CTkLabel(row, text=srv.get("name", "Unknown Server"), font=("Arial", 16, "bold"))
            name_lbl.pack(side="left", padx=15, pady=15)
            
            load_lbl = ctk.CTkLabel(row, text=f"Load: {srv.get('load', '0%')}", text_color="gray")
            load_lbl.pack(side="left", padx=20)
            
            conn_btn = ctk.CTkButton(row, text="Connect", width=80, 
                                     fg_color="#2E7D32", hover_color="#1B5E20",
                                     command=lambda s=srv: self.controller.start_vpn(
                                         s, show_console=self.show_console_var.get()
                                     ))
            conn_btn.pack(side="right", padx=15)

    def logoff(self):
        if not self.controller.current_user or self.controller.waiting_response: return
        
        self.controller.stop_vpn(switch_page=False)
            
        self.logoff_btn.configure(state="disabled")
        self.controller.set_waiting(True)
        payload = {"cmd": "LOGF", "username": self.controller.current_user}
        self.controller.secure.send_json(payload)


class ConnectedPage(BasePage):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        
        # --- Top Navigation Bar ---
        self.nav_bar = ctk.CTkFrame(self, height=50, fg_color="transparent")
        self.nav_bar.pack(fill="x", padx=20, pady=10)

        self.title_label = ctk.CTkLabel(self.nav_bar, text="Secure Connection", font=("Arial", 28, "bold"))
        self.title_label.pack(side="left")

        self.user_btn = ctk.CTkButton(self.nav_bar, text="👤", width=40, height=40, 
                                      font=("Arial", 20), command=self.toggle_menu)
        self.user_btn.pack(side="right")

        # --- Dropdown Profile Menu ---
        self.menu_visible = False
        self.menu_frame = ctk.CTkFrame(self, width=150, corner_radius=10, border_width=1, border_color="gray30")
        
        self.user_label = ctk.CTkLabel(self.menu_frame, text="", font=("Arial", 14))
        self.user_label.pack(pady=(10, 5), padx=15)

        self.logoff_btn = ctk.CTkButton(self.menu_frame, text="Log Off", command=self.logoff, 
                                        fg_color="#C62828", hover_color="#B71C1C", width=100)
        self.logoff_btn.pack(pady=(5, 10), padx=15)

        # --- Center Dashboard Content ---
        self.center_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.center_frame.pack(expand=True)

        self.status_icon = ctk.CTkLabel(self.center_frame, text="🔒", font=("Arial", 80))
        self.status_icon.pack(pady=10)

        self.status_label = ctk.CTkLabel(self.center_frame, text="Connected to:", font=("Arial", 20))
        self.status_label.pack(pady=5)

        self.server_name_label = ctk.CTkLabel(self.center_frame, text="Server Name", font=("Arial", 32, "bold"), text_color="#2E7D32")
        self.server_name_label.pack(pady=10)

        self.disconnect_btn = ctk.CTkButton(self.center_frame, text="Disconnect", width=200, height=50,
                                            font=("Arial", 18, "bold"), fg_color="#C62828", hover_color="#B71C1C",
                                            command=self.controller.stop_vpn)
        self.disconnect_btn.pack(pady=30)

    def toggle_menu(self):
        if self.menu_visible:
            self.menu_frame.place_forget()
            self.menu_visible = False
        else:
            self.menu_frame.place(relx=1.0, rely=0.0, x=-20, y=60, anchor="ne")
            self.menu_frame.tkraise()
            self.menu_visible = True

    def clear_fields(self):
        self.menu_frame.place_forget()
        self.menu_visible = False
        self.logoff_btn.configure(state="normal")
        
        if self.controller.current_user:
            self.user_label.configure(text=f"Logged in as:\n{self.controller.current_user}")
        
        if self.controller.connected_server:
            self.server_name_label.configure(text=self.controller.connected_server.get("name", "Unknown Server"))

    def logoff(self):
        if not self.controller.current_user or self.controller.waiting_response: return
        
        self.controller.stop_vpn(switch_page=False)
        
        self.logoff_btn.configure(state="disabled")
        self.controller.set_waiting(True)
        payload = {"cmd": "LOGF", "username": self.controller.current_user}
        self.controller.secure.send_json(payload)