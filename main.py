# TrackSmart AI – Tkinter Desktop Version
# Features: User Login, Location Reminder, AI Suggestions, SQLite Storage, Auto Location via IP, Stats & Graphs, Smart AI UI

import tkinter as tk
from tkinter import messagebox, simpledialog
import sqlite3
from datetime import datetime, timedelta
import random
import requests
import matplotlib.pyplot as plt
from collections import Counter
import hashlib
import json
import re
import csv  # Add CSV import
from tkinter import ttk, filedialog
import folium
import webbrowser
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderTimedOut
import time
from tkcalendar import DateEntry
import os

# Add OpenWeatherMap API key
WEATHER_API_KEY = "https://api.openweathermap.org/data/3.0/onecall?lat={lat}&lon={lon}&exclude={part}&appid={API key}"  # Get from openweathermap.org

# --- Database Setup ---
conn = sqlite3.connect("tracksmart.db")
cursor = conn.cursor()

# Create tables
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    email TEXT
)""")
conn.commit()

# Drop and recreate locations table
cursor.execute("DROP TABLE IF EXISTS locations")
conn.commit()

cursor.execute("""
CREATE TABLE IF NOT EXISTS locations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    location TEXT,
    timestamp TEXT,
    latitude REAL,
    longitude REAL
)""")
conn.commit()

cursor.execute("""
CREATE TABLE IF NOT EXISTS reminders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    location TEXT,
    message TEXT,
    triggered INTEGER DEFAULT 0
)""")
conn.commit()

cursor.execute("""
CREATE TABLE IF NOT EXISTS settings (
    user_id INTEGER PRIMARY KEY,
    dark_mode INTEGER DEFAULT 0,
    last_login TEXT
)""")
conn.commit()

cursor.execute("""
CREATE TABLE IF NOT EXISTS user_settings (
    user_id INTEGER PRIMARY KEY,
    theme TEXT DEFAULT 'light',
    notification_enabled INTEGER DEFAULT 1,
    auto_location INTEGER DEFAULT 0
)""")
conn.commit()

cursor.execute("""
CREATE TABLE IF NOT EXISTS location_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    location TEXT,
    note TEXT,
    timestamp TEXT
)""")
conn.commit()

cursor.execute("""
CREATE TABLE IF NOT EXISTS marked_locations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    location TEXT,
    is_favorite INTEGER DEFAULT 0,
    color TEXT DEFAULT 'red'
)""")
conn.commit()

current_user_id = None
session_start = None
TIMEOUT_MINUTES = 30
DARK_MODE = False
current_theme = "light"
SESSION_TIMEOUT = 30  # minutes

# Add custom styles and constants
PADDING = 10
BUTTON_WIDTH = 35
BUTTON_HEIGHT = 2
WINDOW_WIDTH = 800
WINDOW_HEIGHT = 800

# Updated style constants
STYLES = {
    'PRIMARY_COLOR': '#2962ff',
    'SECONDARY_COLOR': '#455a64',
    'BG_COLOR': '#f5f5f5',
    'ACCENT_COLOR': '#00c853',
    'FONT_FAMILY': 'Segoe UI',  # Changed from Helvetica
    'HEADING_SIZE': 14,
    'BUTTON_SIZE': 10,
    'LABEL_SIZE': 10,
    'DARK_BG': '#2b2b2b',
    'DARK_FG': '#ffffff',
    'DARK_ACCENT': '#404040'
}

# Add window size constants
WINDOW_SIZES = {
    'main': "1024x768",
    'login': "400x500",
    'register': "400x550",
    'dashboard': "800x600",
    'settings': "400x500",
    'weather': "400x300",
    'reminders': "600x400",
    'search': "800x600",
    'notes': "500x600",
    'timeline': "800x600"
}

def center_window(window, width, height):
    """Center any window on screen"""
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width - width) // 2
    y = (screen_height - height) // 2
    window.geometry(f"{width}x{height}+{x}+{y}")

def setup_styles():
    style = ttk.Style()
    style.theme_use('clam')  # Use modern clam theme
    
    # Configure base styles for light/dark modes
    def configure_theme(is_dark=False):
        try:
            bg = STYLES['DARK_BG'] if is_dark else STYLES['BG_COLOR']
            fg = STYLES['DARK_FG'] if is_dark else 'black'
            accent = STYLES['DARK_ACCENT'] if is_dark else STYLES['SECONDARY_COLOR']
            
            # Base styles must be configured first
            style.configure('TFrame', background=bg)
            style.configure('TLabel', background=bg, foreground=fg)
            style.configure('TLabelframe', background=bg, foreground=fg)
            style.configure('TLabelframe.Label', background=bg, foreground=fg)
            
            # Button styles
            style.configure('TButton', 
                background=accent,
                foreground=fg,
                padding=6,
                font=(STYLES['FONT_FAMILY'], STYLES['BUTTON_SIZE']))
                
            # Custom button styles
            style.configure('Primary.TButton',
                padding=(20, 10),
                font=(STYLES['FONT_FAMILY'], STYLES['BUTTON_SIZE']),
                background=STYLES['PRIMARY_COLOR'],
                foreground='white')
                
            style.configure('Secondary.TButton',
                padding=(15, 8),
                font=(STYLES['FONT_FAMILY'], STYLES['BUTTON_SIZE']))
                
            style.configure('MenuButton.TButton',
                font=(STYLES['FONT_FAMILY'], 10),
                padding=8)
                
            # Section styles
            style.configure('Section.TLabelframe',
                background=bg,
                foreground=fg,
                padding=10,
                font=(STYLES['FONT_FAMILY'], STYLES['LABEL_SIZE']))
                
            style.configure('Section.TLabelframe.Label',
                font=(STYLES['FONT_FAMILY'], STYLES['HEADING_SIZE'], 'bold'),
                foreground=STYLES['SECONDARY_COLOR'],
                background=bg)
                
            # Other widget styles
            style.configure('TEntry', fieldbackground=bg, foreground=fg)
            style.configure('TNotebook', background=bg)
            style.configure('TNotebook.Tab', background=accent, foreground=fg)
            style.configure('TScrollbar',
                background=accent,
                troughcolor=bg,
                width=10,
                arrowsize=13)
                
            # Heading styles
            style.configure('Header.TLabel',
                font=(STYLES['FONT_FAMILY'], 24, 'bold'),
                foreground=STYLES['PRIMARY_COLOR'],
                background=bg,
                padding=15)
                
            style.configure('Heading.TLabel',
                font=(STYLES['FONT_FAMILY'], 16, 'bold'),
                foreground=STYLES['PRIMARY_COLOR'],
                background=bg,
                padding=(0, 20))
                
            style.configure('Regular.TLabel',
                font=(STYLES['FONT_FAMILY'], STYLES['LABEL_SIZE']),
                background=bg,
                padding=5)
                
            # Button hover effects
            style.map('MenuButton.TButton',
                background=[('active', STYLES['PRIMARY_COLOR'])],
                foreground=[('active', 'white')])
                
        except tk.TclError as e:
            print(f"Style error: {e}")
            # Fallback to basic styles if custom ones fail
            style.configure('TFrame', background='white')
            style.configure('TLabel', background='white')
            style.configure('TButton', padding=5)

    # Initial light mode setup
    configure_theme(False)
    root.configure_theme = configure_theme

def apply_theme(theme_name):
    global current_theme
    current_theme = theme_name
    root.configure_theme(theme_name == "dark")
    
    # Update window background
    bg_color = STYLES['DARK_BG'] if theme_name == "dark" else STYLES['BG_COLOR']
    root.configure(bg=bg_color)
    
    # Force refresh all widgets
    for widget in root.winfo_children():
        widget.update()

def create_scrollable_frame(parent):
    container = ttk.Frame(parent)
    canvas = tk.Canvas(container, highlightthickness=0)  # Remove border
    scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
    
    # Configure scrollbar style
    scrollbar.config(style='TScrollbar')
    
    # Enhanced mouse wheel scrolling
    def _on_mousewheel(event):
        canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    
    canvas.bind_all("<MouseWheel>", _on_mousewheel)
    
    scrollable_frame = ttk.Frame(canvas)

    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )

    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    container.pack(fill="both", expand=True, padx=PADDING, pady=PADDING)
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    return scrollable_frame

# --- AI Assistant Logic ---
def ai_suggestion():
    now = datetime.now()
    hour = now.hour
    if hour < 12:
        return "Good morning! Don't forget to review your schedule."
    elif 12 <= hour < 18:
        return "Good afternoon! Have you completed your goals for today?"
    else:
        return "Good evening! Time to relax or plan for tomorrow."

def smart_note_suggestions(note_text):
    """
    Placeholder: Use GPT or spaCy to analyze and tag notes.
    For now, returns a dummy tag.
    """
    if "exam" in note_text.lower():
        return "exam"
    elif "shop" in note_text.lower():
        return "shopping"
    return "general"

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def validate_input(username, password):
    if len(username) < 3 or len(password) < 6:
        return False
    return True

def validate_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

def check_session():
    global current_user_id, session_start
    if not current_user_id:
        return False
    if session_start and datetime.now() - session_start > timedelta(minutes=TIMEOUT_MINUTES):
        current_user_id = None
        session_start = None
        messagebox.showwarning("Session Expired", "Please login again")
        show_login_menu()
        return False
    return True

def create_login_window():
    """Create styled login window"""
    login_win = tk.Toplevel(root)
    login_win.title("Login - TrackSmart AI")
    
    # Ensure window is created with correct size and position
    width, height = map(int, WINDOW_SIZES['login'].split('x'))
    center_window(login_win, width, height)
    login_win.grab_set()
    
    # Create main container with style
    frame = ttk.Frame(login_win, style='TFrame')
    frame.pack(fill='both', expand=True, padx=20, pady=20)
    
    # Header
    ttk.Label(frame, text="Welcome Back", 
             style='Header.TLabel').pack(pady=(0,20))
             
    # Username
    ttk.Label(frame, text="Username:", 
             style='Regular.TLabel').pack(anchor='w', pady=(10,0))
    user_entry = ttk.Entry(frame, width=40)
    user_entry.pack(fill='x', pady=(5,10))
    
    # Password
    ttk.Label(frame, text="Password:", 
             style='Regular.TLabel').pack(anchor='w', pady=(10,0))
    pass_entry = ttk.Entry(frame, show="*", width=40)
    pass_entry.pack(fill='x', pady=(5,20))
    
    return login_win, user_entry, pass_entry

def create_register_window():
    """Create styled registration window"""
    reg_win = tk.Toplevel(root)
    reg_win.title("Register - TrackSmart AI")
    width, height = map(int, WINDOW_SIZES['register'].split('x'))
    center_window(reg_win, width, height)
    reg_win.grab_set()  # Make window modal
    
    # Create main frame with padding
    frame = ttk.Frame(reg_win, padding="20")
    frame.pack(fill='both', expand=True)
    
    # Header
    ttk.Label(frame, text="Create Account", 
             style='Header.TLabel').pack(pady=(0,20))
             
    # Username
    ttk.Label(frame, text="Username:", 
             style='Regular.TLabel').pack(anchor='w', pady=(10,0))
    user_entry = ttk.Entry(frame, width=40)
    user_entry.pack(fill='x', pady=(5,10))
    
    # Password
    ttk.Label(frame, text="Password:", 
             style='Regular.TLabel').pack(anchor='w', pady=(10,0))
    pass_entry = ttk.Entry(frame, show="*", width=40)
    pass_entry.pack(fill='x', pady=(5,10))
    
    # Email
    ttk.Label(frame, text="Email:", 
             style='Regular.TLabel').pack(anchor='w', pady=(10,0))
    email_entry = ttk.Entry(frame, width=40)
    email_entry.pack(fill='x', pady=(5,20))
    
    return reg_win, user_entry, pass_entry, email_entry

def validate_password_strength(password):
    """Check if password meets minimum security requirements"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    return True, "Password is strong"

def sanitize_input(text):
    """Remove potentially dangerous characters"""
    return re.sub(r'[;<>&$]', '', text.strip())

def check_username_exists(username):
    """Check if username is already taken"""
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
    return cursor.fetchone()[0] > 0

def register():
    reg_win, user_entry, pass_entry, email_entry = create_register_window()
    
    def do_register():
        username = sanitize_input(user_entry.get())
        password = sanitize_input(pass_entry.get())
        email = sanitize_input(email_entry.get())
        
        # Validate all fields are filled
        if not all([username, password, email]):
            messagebox.showerror("Error", "All fields are required")
            return
            
        # Check username length and characters
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
            messagebox.showerror("Error", "Username must be 3-20 characters long and contain only letters, numbers, and underscores")
            return
            
        # Check if username exists
        if check_username_exists(username):
            messagebox.showerror("Error", "Username already exists")
            return
            
        # Validate password strength
        is_valid, msg = validate_password_strength(password)
        if not is_valid:
            messagebox.showerror("Error", msg)
            return
            
        # Validate email
        if not validate_email(email):
            messagebox.showerror("Error", "Invalid email format")
            return
            
        try:
            hashed_pwd = hash_password(password)
            cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", 
                         (username, hashed_pwd, email))
            user_id = cursor.lastrowid
            
            # Initialize user settings
            cursor.execute("INSERT INTO user_settings (user_id, theme) VALUES (?, ?)", (user_id, 'light'))
            cursor.execute("INSERT INTO settings (user_id, last_login) VALUES (?, ?)", (user_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            
            conn.commit()
            messagebox.showinfo("Success", "Registration complete! You can now login.")
            reg_win.destroy()
            
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "An error occurred during registration")
        except Exception as e:
            messagebox.showerror("Error", f"Registration failed: {str(e)}")

    ttk.Button(reg_win, text="Register", 
              style='Primary.TButton',
              command=do_register).pack(pady=20)
    
    # Add password requirements label
    ttk.Label(reg_win, text="Password must contain:\n" +
             "- At least 8 characters\n" +
             "- One uppercase letter\n" +
             "- One lowercase letter\n" +
             "- One number",
             style='Regular.TLabel').pack(pady=10)
    
    user_entry.focus()

def login():
    login_win, user_entry, pass_entry = create_login_window()
    
    def do_login():
        global current_user_id, session_start
        username = sanitize_input(user_entry.get())
        password = sanitize_input(pass_entry.get())
        
        if not username or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
            
        try:
            cursor.execute("SELECT id, password FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            
            if result and hash_password(password) == result[1]:
                current_user_id = result[0]
                session_start = datetime.now()
                
                # Update last login
                cursor.execute("UPDATE settings SET last_login = ? WHERE user_id = ?", 
                             (session_start.strftime("%Y-%m-%d %H:%M:%S"), current_user_id))
                
                # Get theme preference
                cursor.execute("SELECT theme FROM user_settings WHERE user_id = ?", (current_user_id,))
                theme_result = cursor.fetchone()
                
                conn.commit()
                apply_theme(theme_result[0] if theme_result and theme_result[0] else 'light')
                
                # Show success message
                messagebox.showinfo("Welcome", f"Welcome back, {username}!")
                
                show_main_menu()
                login_win.destroy()
            else:
                messagebox.showerror("Error", "Invalid username or password")
                pass_entry.delete(0, tk.END)
                
        except Exception as e:
            messagebox.showerror("Error", f"Login failed: {str(e)}")
            
        # Add attempt tracking here if needed
        
    ttk.Button(login_win, text="Login", 
              style='Primary.TButton',
              command=do_login).pack(pady=20)
    
    # Add forgot password option (placeholder)
    ttk.Button(login_win, text="Forgot Password?",
              style='Secondary.TButton',
              command=lambda: messagebox.showinfo("Info", "Please contact admin to reset password")
              ).pack(pady=5)
    
    user_entry.focus()

def logout():
    global current_user_id, session_start
    current_user_id = None
    session_start = None
    show_login_menu()

# --- Core Functions ---
def log_location():
    """
    Manually log a user's location with timestamp and coordinates.
    Requires user to be logged in.
    """
    if not current_user_id:
        messagebox.showerror("Error", "Please login first!")
        return
    location = simpledialog.askstring("Log Location", "Enter your current location:")
    if location and location.strip():
        save_location(location.strip())

def auto_log_location():
    """
    Automatically detect and log user's location using IP geolocation.
    Requires user to be logged in and internet connection.
    """
    if not current_user_id:
        messagebox.showerror("Error", "Please login first!")
        return
    
    if not check_session():
        show_login_menu()
        return
        
    try:
        response = requests.get("https://ipinfo.io/json")
        data = response.json()
        city = data.get("city", "Unknown")
        region = data.get("region", "")
        location = f"{city}, {region}".strip(', ')
        save_location(location)
    except Exception as e:
        messagebox.showerror("Error", f"Could not fetch location: {e}")

def geocode_location(location_name):
    try:
        geolocator = Nominatim(user_agent="tracksmart_ai")
        location = geolocator.geocode(location_name)
        if location:
            return location.latitude, location.longitude
        return None, None
    except (GeocoderTimedOut, Exception) as e:
        print(f"Geocoding error: {e}")
        return None, None

def get_weather(location):
    try:
        url = f"http://api.openweathermap.org/data/2.5/weather?q={location}&appid={WEATHER_API_KEY}&units=metric"
        response = requests.get(url)
        data = response.json()
        if response.status_code == 200:
            return {
                'temp': data['main']['temp'],
                'humidity': data['main']['humidity'],
                'condition': data['weather'][0]['main'],
                'description': data['weather'][0]['description']
            }
        return None
    except Exception as e:
        print(f"Weather API error: {e}")
        return None

def show_weather_info(location):
    weather = get_weather(location)
    if weather:
        weather_win = tk.Toplevel(root)
        weather_win.title(f"Weather in {location}")
        weather_win.geometry("300x200")
        
        ttk.Label(weather_win, text=f"Temperature: {weather['temp']}°C").pack(pady=5)
        ttk.Label(weather_win, text=f"Condition: {weather['condition']}").pack(pady=5)
        ttk.Label(weather_win, text=f"Humidity: {weather['humidity']}%").pack(pady=5)
        ttk.Label(weather_win, text=f"Description: {weather['description']}").pack(pady=5)
        
        ttk.Button(weather_win, text="Close", command=weather_win.destroy).pack(pady=10)

def save_location(location):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lat, lon = geocode_location(location)
    
    cursor.execute("""
        INSERT INTO locations (user_id, location, timestamp, latitude, longitude) 
        VALUES (?, ?, ?, ?, ?)
    """, (current_user_id, location, timestamp, lat, lon))
    conn.commit()
    messagebox.showinfo("Success", f"Location '{location}' logged at {timestamp}.")
    show_weather_info(location)  # Show weather after saving
    check_reminders(location)

def add_reminder():
    location = simpledialog.askstring("Set Reminder", "Enter location to trigger reminder:")
    message = simpledialog.askstring("Set Reminder", "Enter your reminder message:")
    if location and message:
        cursor.execute("INSERT INTO reminders (user_id, location, message) VALUES (?, ?, ?)",
                       (current_user_id, location, message))
        conn.commit()
        messagebox.showinfo("Reminder Set", f"Reminder for '{location}' saved.")

def manage_reminders():
    if not current_user_id:
        messagebox.showerror("Error", "Please login first!")
        return

    rem_win = tk.Toplevel(root)
    rem_win.title("Manage Reminders")
    rem_win.geometry("450x300")

    tk.Label(rem_win, text="Your Reminders", font=("Arial", 14)).pack(pady=5)

    listbox = tk.Listbox(rem_win, width=60)
    listbox.pack(padx=10, pady=5)

    # Fetch user reminders
    cursor.execute("SELECT id, location, message FROM reminders WHERE user_id = ?", (current_user_id,))
    reminders = cursor.fetchall()

    for rid, loc, msg in reminders:
        listbox.insert(tk.END, f"📍 {loc} → {msg} (ID: {rid})")

    def delete_selected():
        selection = listbox.curselection()
        if selection:
            selected = listbox.get(selection[0])
            rid = int(selected.split('(ID: ')[1].rstrip(')'))
            cursor.execute("DELETE FROM reminders WHERE id = ?", (rid,))
            conn.commit()
            listbox.delete(selection[0])
            messagebox.showinfo("Deleted", "Reminder deleted.")

    tk.Button(rem_win, text="🗑️ Delete Selected", command=delete_selected).pack(pady=5)
    tk.Button(rem_win, text="Close", command=rem_win.destroy).pack(pady=5)

def check_reminders(current_location):
    cursor.execute("SELECT id, message FROM reminders WHERE user_id = ? AND location = ? AND triggered = 0",
                   (current_user_id, current_location))
    rows = cursor.fetchall()
    for rid, msg in rows:
        messagebox.showinfo("Location Reminder", f"Reminder: {msg}")
        cursor.execute("UPDATE reminders SET triggered = 1 WHERE id = ?", (rid,))
    conn.commit()

def show_dashboard():
    if not current_user_id:
        messagebox.showerror("Error", "Please login first!")
        return

    dash_win = tk.Toplevel(root)
    dash_win.title("Location Dashboard")
    dash_win.geometry("500x400")

    frame = ttk.Frame(dash_win)
    frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    ttk.Label(frame, text="Recent Location History", font=("Arial", 14, "bold")).pack(pady=10)

    # Create Treeview with scrollbar
    tree_frame = ttk.Frame(frame)
    tree_frame.pack(fill=tk.BOTH, expand=True)

    tree = ttk.Treeview(tree_frame, columns=("Location", "Date", "Time"), show="headings")
    vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
    
    tree.configure(yscrollcommand=vsb.set)
    
    tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    vsb.pack(side=tk.RIGHT, fill=tk.Y)

    for col in ("Location", "Date", "Time"):
        tree.heading(col, text=col)
        tree.column(col, width=150)

    def load_data():
        for item in tree.get_children():
            tree.delete(item)
            
        cursor.execute("""
            SELECT location, timestamp 
            FROM locations 
            WHERE user_id = ? 
            ORDER BY timestamp DESC
        """, (current_user_id,))
        
        rows = cursor.fetchall()
        if not rows:
            ttk.Label(frame, text="No locations recorded yet", 
                     font=("Arial", 12)).pack(pady=20)
            return False
            
        for location, timestamp in rows:
            try:
                dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                tree.insert("", tk.END, values=(
                    location,
                    dt.strftime("%Y-%m-%d"),
                    dt.strftime("%H:%M:%S")
                ))
            except ValueError:
                continue
        return True

    if load_data():
        ttk.Button(frame, text="🔄 Refresh", command=load_data).pack(pady=5)
    ttk.Button(frame, text="Close", command=dash_win.destroy).pack(pady=5)

def show_location_stats():
    if not current_user_id:
        messagebox.showerror("Error", "Please login first!")
        return

    cursor.execute("""
        SELECT location, COUNT(*) as count 
        FROM locations 
        WHERE user_id = ?
        GROUP BY location 
        ORDER BY count DESC
    """, (current_user_id,))
    
    rows = cursor.fetchall()
    if not rows:
        messagebox.showinfo("Stats", "No location data available.\nStart by logging some locations!")
        return

    plt.figure(figsize=(10, 6))
    locations = [row[0] for row in rows]
    counts = [row[1] for row in rows]
    
    bars = plt.bar(range(len(locations)), counts, color='skyblue')
    plt.title("Most Visited Locations", pad=20)
    plt.xlabel("Location")
    plt.ylabel("Number of Visits")
    
    # Rotate labels for better readability
    plt.xticks(range(len(locations)), locations, rotation=45, ha='right')
    
    # Add value labels on top of bars
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}', ha='center', va='bottom')
    
    plt.tight_layout()
    plt.show()

def export_logs_to_csv():
    if not current_user_id:
        messagebox.showerror("Error", "Please login first!")
        return

    # Create date picker window
    date_win = tk.Toplevel(root)
    date_win.title("Select Date Range")
    date_win.geometry("300x200")

    ttk.Label(date_win, text="Start Date:").pack(pady=5)
    start_date = DateEntry(date_win, width=30, background='darkblue', foreground='white')
    start_date.pack(pady=5)

    ttk.Label(date_win, text="End Date:").pack(pady=5)
    end_date = DateEntry(date_win, width=30, background='darkblue', foreground='white')
    end_date.pack(pady=5)

    def export_range():
        start = start_date.get_date()
        end = end_date.get_date()
        
        if start > end:
            messagebox.showerror("Error", "Start date must be before end date")
            return

        # Format dates for SQL query
        start_str = start.strftime("%Y-%m-%d 00:00:00")
        end_str = end.strftime("%Y-%m-%d 23:59:59")

        cursor.execute("""
            SELECT location, timestamp 
            FROM locations 
            WHERE user_id = ? 
            AND timestamp BETWEEN ? AND ?
            ORDER BY timestamp
        """, (current_user_id, start_str, end_str))
        
        rows = cursor.fetchall()

        if not rows:
            messagebox.showinfo("Export", "No data found in selected date range")
            return

        try:
            filename = f"tracksmart_logs_{start.strftime('%Y%m%d')}-{end.strftime('%Y%m%d')}.csv"
            with open(filename, mode="w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow(["Location", "Timestamp"])
                for loc, ts in rows:
                    writer.writerow([loc, ts])
            
            messagebox.showinfo("Export Complete", f"Data exported to '{filename}'")
            date_win.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {str(e)}")

    ttk.Button(date_win, text="Export", command=export_range).pack(pady=20)

def open_ai_assistant():
    ai_win = tk.Toplevel(root)
    ai_win.title("AI Assistant")
    ai_win.geometry("350x200")

    suggestion = ai_suggestion()
    tk.Label(ai_win, text="AI Suggestion:", font=("Arial", 12)).pack(pady=10)
    tk.Message(ai_win, text=suggestion, width=300, font=("Arial", 10)).pack(pady=5)

    tk.Button(ai_win, text="Back to Menu", command=ai_win.destroy).pack(pady=10)

def toggle_theme():
    global DARK_MODE
    DARK_MODE = not DARK_MODE
    style = ttk.Style()
    if DARK_MODE:
        root.configure(bg='#2b2b2b')
        style.configure("TButton", background='#404040', foreground='white')
        style.configure("TLabel", background='#2b2b2b', foreground='white')
    else:
        root.configure(bg='#f0f0f0')
        style.configure("TButton", background='#e0e0e0', foreground='black')
        style.configure("TLabel", background='#f0f0f0', foreground='black')

def export_data():
    if not check_session():
        return
        
    file_path = filedialog.asksaveasfilename(
        defaultextension=".json",
        filetypes=[("JSON files", "*.json")]
    )
    if not file_path:
        return
        
    cursor.execute("SELECT location, timestamp FROM locations WHERE user_id = ?", 
                  (current_user_id,))
    data = {"locations": [{"location": loc, "time": ts} for loc, ts in cursor.fetchall()]}
    
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)
    messagebox.showinfo("Success", "Data exported successfully")

def show_map_with_locations():
    # Update existing map function to use stored coordinates
    if not current_user_id:
        messagebox.showerror("Error", "Please login first!")
        return

    cursor.execute("""
        SELECT location, latitude, longitude 
        FROM locations 
        WHERE user_id = ? AND latitude IS NOT NULL
    """, (current_user_id,))
    
    rows = cursor.fetchall()
    if not rows:
        messagebox.showinfo("Map", "No location data available to map.")
        return

    # Use first location as center, or default to India
    center_lat, center_lon = rows[0][1], rows[0][2] if rows else (20.5937, 78.9629)
    map_obj = folium.Map(location=[center_lat, center_lon], zoom_start=5)

    for loc_name, lat, lon in rows:
        folium.Marker(
            location=[lat, lon],
            popup=f"{loc_name}",
            icon=folium.Icon(color='red', icon='info-sign')
        ).add_to(map_obj)

    map_file = "location_map.html"
    map_obj.save(map_file)
    webbrowser.open(map_file)

def show_activity_timeline():
    if not current_user_id:
        messagebox.showerror("Error", "Please login first!")
        return

    timeline_win = tk.Toplevel(root)
    timeline_win.title("Activity Timeline")
    timeline_win.geometry("600x500")

    frame = ttk.Frame(timeline_win)
    frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    ttk.Label(frame, text="Your Activity Timeline", font=("Arial", 14, "bold")).pack(pady=10)

    canvas = tk.Canvas(frame)
    scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
    scrollable_frame = ttk.Frame(canvas)

    canvas.configure(yscrollcommand=scrollbar.set)

    cursor.execute("""
        SELECT location, timestamp, latitude, longitude
        FROM locations 
        WHERE user_id = ? 
        ORDER BY timestamp DESC
    """, (current_user_id,))
    
    activities = cursor.fetchall()

    if not activities:
        ttk.Label(frame, text="No activities recorded yet", font=("Arial", 12)).pack(pady=20)
        return

    for loc, ts, lat, lon in activities:
        activity_frame = ttk.Frame(scrollable_frame)
        activity_frame.pack(fill="x", pady=5)
        
        dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        ttk.Label(activity_frame, text=f"📍 {loc}").pack(side="left", padx=5)
        ttk.Label(activity_frame, text=dt.strftime("%Y-%m-%d %H:%M")).pack(side="right", padx=5)
        if lat and lon:
            ttk.Label(activity_frame, text=f"({lat:.4f}, {lon:.4f})").pack(side="right", padx=5)

    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

def clear_all_data():
    if not current_user_id:
        messagebox.showerror("Error", "Please login first!")
        return
        
    if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete all your data? This cannot be undone!"):
        try:
            cursor.execute("DELETE FROM locations WHERE user_id = ?", (current_user_id,))
            cursor.execute("DELETE FROM reminders WHERE user_id = ?", (current_user_id,))
            conn.commit()
            messagebox.showinfo("Success", "All your data has been cleared.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to clear data: {e}")

def manage_location_notes(location):
    notes_win = tk.Toplevel(root)
    notes_win.title(f"Notes for {location}")
    notes_win.geometry("400x500")

    notes_frame = ttk.Frame(notes_win)
    notes_frame.pack(fill='both', expand=True, padx=10, pady=5)

    # Add note section with tag display
    ttk.Label(notes_frame, text="Add New Note:").pack(pady=5)
    note_entry = ttk.Entry(notes_frame, width=40)
    note_entry.pack(pady=5)
    tag_label = ttk.Label(notes_frame, text="Tag: general", style='Regular.TLabel')
    tag_label.pack(pady=2)

    def update_tag(*args):
        tag = smart_note_suggestions(note_entry.get())
        tag_label.config(text=f"Tag: {tag}")

    note_entry.bind('<KeyRelease>', update_tag)

    def add_note():
        note = note_entry.get().strip()
        if note:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("""
                INSERT INTO location_notes (user_id, location, note, timestamp)
                VALUES (?, ?, ?, ?)
            """, (current_user_id, location, note, timestamp))
            conn.commit()
            note_entry.delete(0, tk.END)
            refresh_notes()

    ttk.Button(notes_frame, text="Add Note", command=add_note).pack(pady=5)

    # Notes list
    notes_list = ttk.Treeview(notes_frame, columns=("Note", "Date"), show="headings")
    notes_list.heading("Note", text="Note")
    notes_list.heading("Date", text="Date")
    notes_list.pack(pady=10, fill='both', expand=True)

    def refresh_notes():
        for item in notes_list.get_children():
            notes_list.delete(item)
        cursor.execute("""
            SELECT id, note, timestamp 
            FROM location_notes 
            WHERE user_id = ? AND location = ?
            ORDER BY timestamp DESC
        """, (current_user_id, location))
        for note_id, note, ts in cursor.fetchall():
            notes_list.insert("", "end", values=(note, ts), tags=(note_id,))

    def delete_note():
        selected = notes_list.selection()
        if selected:
            note_id = notes_list.item(selected[0])['tags'][0]
            if messagebox.askyesno("Confirm", "Delete this note?"):
                cursor.execute("DELETE FROM location_notes WHERE id = ?", (note_id,))
                conn.commit()
                refresh_notes()

    ttk.Button(notes_frame, text="Delete Selected", command=delete_note).pack(pady=5)
    refresh_notes()

def toggle_marked_location(location):
    cursor.execute("""
        SELECT id FROM marked_locations 
        WHERE user_id = ? AND location = ?
    """, (current_user_id, location))
    
    if cursor.fetchone():
        cursor.execute("""
            DELETE FROM marked_locations 
            WHERE user_id = ? AND location = ?
        """, (current_user_id, location))
        status = "unmarked"
    else:
        cursor.execute("""
            INSERT INTO marked_locations (user_id, location) 
            VALUES (?, ?)
        """, (current_user_id, location))
        status = "marked"
    
    conn.commit()
    messagebox.showinfo("Success", f"Location {status} successfully!")

def search_location_history():
    search_win = tk.Toplevel(root)
    search_win.title("Search Locations")
    search_win.geometry("500x600")

    ttk.Label(search_win, text="Search Location:").pack(pady=5)
    search_entry = ttk.Entry(search_win, width=40)
    search_entry.pack(pady=5)

    results_frame = ttk.Frame(search_win)
    results_frame.pack(fill='both', expand=True, padx=10, pady=5)

    def do_search():
        search_term = search_entry.get().strip()
        if search_term:
            # Clear previous results
            for widget in results_frame.winfo_children():
                widget.destroy()

            # Get visit count
            cursor.execute("""
                SELECT COUNT(*) 
                FROM locations 
                WHERE user_id = ? AND location LIKE ?
            """, (current_user_id, f"%{search_term}%"))
            
            visit_count = cursor.fetchone()[0]
            ttk.Label(results_frame, 
                     text=f"Found {visit_count} visits").pack(pady=5)

            # Get timeline
            cursor.execute("""
                SELECT location, timestamp 
                FROM locations 
                WHERE user_id = ? AND location LIKE ? 
                ORDER BY timestamp DESC
            """, (current_user_id, f"%{search_term}%"))
            
            timeline = ttk.Treeview(results_frame, 
                                  columns=("Location", "Date"),
                                  show="headings")
            timeline.heading("Location", text="Location")
            timeline.heading("Date", text="Date")
            timeline.pack(pady=5, fill='both', expand=True)

            for loc, ts in cursor.fetchall():
                timeline.insert("", "end", values=(loc, ts))

            # Get notes
            cursor.execute("""
                SELECT note, timestamp 
                FROM location_notes 
                WHERE user_id = ? AND location LIKE ? 
                ORDER BY timestamp DESC
            """, (current_user_id, f"%{search_term}%"))
            
            ttk.Label(results_frame, text="Notes:", font=("Arial", 10, "bold")).pack(pady=5)
            notes_text = tk.Text(results_frame, height=5, width=50)
            notes_text.pack(pady=5)
            
            notes = cursor.fetchall()
            if notes:
                for note, ts in notes:
                    notes_text.insert("end", f"[{ts}] {note}\n")
            else:
                notes_text.insert("end", "No notes found")
            
            notes_text.config(state='disabled')

    ttk.Button(search_win, text="Search", command=do_search).pack(pady=5)

# --- GUI Menus ---
def show_main_menu():
    if not check_session():
        return
        
    for widget in root.winfo_children():
        widget.destroy()

    # Main container with explicit style
    main = ttk.Frame(root, style='TFrame')
    main.pack(fill='both', expand=True, padx=20, pady=10)

    # Header with extra spacing
    header = ttk.Frame(main)
    header.pack(fill='x', pady=(0,20))
    
    ttk.Label(header, text="TrackSmart AI", 
             style='Header.TLabel').pack(side='left', pady=(0, 10))
    ttk.Button(header, text="👋 Logout", 
               style='MenuButton.TButton', 
               command=logout).pack(side='right', pady=10)

    # Content sections
    content = ttk.Frame(main)
    content.pack(fill='both', expand=True)
    
    # Make columns equal width
    content.columnconfigure(0, weight=1)
    content.columnconfigure(1, weight=1)

    # Location Tools Section
    loc_frame = ttk.LabelFrame(content, text="📍 Location Tools", style='Section.TLabelframe')
    loc_frame.grid(row=0, column=0, padx=5, pady=5, sticky='nsew')
    
    for btn_text, cmd in [
        ("Log Location (Manual)", log_location),
        ("Auto-Detect Location", auto_log_location),
        ("View Dashboard", show_dashboard),
        ("View Map", show_map_with_locations)
    ]:
        ttk.Button(loc_frame, text=btn_text, style='MenuButton.TButton',
                  command=cmd).pack(padx=5, pady=3, fill='x')

    # Analytics Section
    analytics_frame = ttk.LabelFrame(content, text="📊 Analytics", style='Section.TLabelframe')
    analytics_frame.grid(row=0, column=1, padx=5, pady=5, sticky='nsew')
    
    for btn_text, cmd in [
        ("Location Statistics", show_location_stats),
        ("Activity Timeline", show_activity_timeline),
        ("Search History", search_location_history),
        ("Export Data", export_data)
    ]:
        ttk.Button(analytics_frame, text=btn_text, style='MenuButton.TButton',
                  command=cmd).pack(padx=5, pady=3, fill='x')

    # Tools Section
    tools_frame = ttk.LabelFrame(content, text="🛠️ Tools", style='Section.TLabelframe')
    tools_frame.grid(row=1, column=0, padx=5, pady=5, sticky='nsew')
    
    for btn_text, cmd in [
        ("Set Reminder", add_reminder),
        ("Manage Reminders", manage_reminders),
        ("AI Assistant", open_ai_assistant),
        ("Export to CSV", export_logs_to_csv)
    ]:
        ttk.Button(tools_frame, text=btn_text, style='MenuButton.TButton',
                  command=cmd).pack(padx=5, pady=3, fill='x')

    # Settings Section
    settings_frame = ttk.LabelFrame(content, text="⚙️ Settings", style='Section.TLabelframe')
    settings_frame.grid(row=1, column=1, padx=5, pady=5, sticky='nsew')
    
    for btn_text, cmd in [
        ("App Settings", show_settings),
        ("Toggle Theme", toggle_theme),
        ("Clear All Data", clear_all_data)
    ]:
        ttk.Button(settings_frame, text=btn_text, style='MenuButton.TButton',
                  command=cmd).pack(padx=5, pady=3, fill='x')

    # Footer with adjusted padding
    footer = ttk.Frame(main)
    footer.pack(fill='x', pady=(15, 5))
    ttk.Label(footer, text="TrackSmart AI v1.0", 
             style='Regular.TLabel').pack(side='right')

def show_login_menu():
    for widget in root.winfo_children():
        widget.destroy()

    login_frame = ttk.Frame(root, style='Main.TFrame', padding=20)
    login_frame.pack(fill='both', expand=True)
    
    login_frame.grid_rowconfigure(0, weight=1)
    login_frame.grid_rowconfigure(5, weight=1)  # Updated to accommodate new button
    login_frame.grid_columnconfigure(0, weight=1)
    
    ttk.Label(login_frame,
             text="Welcome to TrackSmart AI",
             style='Heading.TLabel').grid(row=1, pady=20)
             
    ttk.Button(login_frame,
              text="🔐 Login",
              style='Primary.TButton',
              width=30,
              command=login).grid(row=2, pady=5)
              
    ttk.Button(login_frame,
              text="🆕 Register",
              style='Secondary.TButton', 
              width=30,
              command=register).grid(row=3, pady=5)
              
    ttk.Button(login_frame,
              text="📖 User Guide",
              style='Secondary.TButton',
              width=30,
              command=show_guidebook).grid(row=4, pady=5)

def show_guidebook():
    guide_win = tk.Toplevel(root)
    guide_win.title("TrackSmart AI - User Guide")
    guide_win.geometry("600x700")
    
    # Create scrollable frame for content
    guide_frame = create_scrollable_frame(guide_win)
    
    sections = {
        "Getting Started": """
• Login or Register: Create an account to start using TrackSmart AI
• After logging in, you'll see the main dashboard with various tools
""",
        "Location Tools": """
• Manual Log: Enter your location manually
• Auto-Detect: Let the app detect your location automatically
• Dashboard: View your location history
• Map View: See your locations on an interactive map
""",
        "Analytics": """
• Location Statistics: View graphs of your most visited places
• Activity Timeline: See your movement patterns over time
• Search History: Find specific location entries
• Export Data: Save your data in various formats
""",
        "Tools": """
• Set Reminder: Create location-based reminders
• Manage Reminders: Edit or delete your reminders
• AI Assistant: Get smart suggestions based on your patterns
• Export to CSV: Download your data in spreadsheet format
""",
        "Settings": """
• Theme: Switch between light and dark modes
• Auto-Location: Enable/disable automatic location detection
• Data Management: Options to manage or clear your data
"""
    }
    
    ttk.Label(guide_frame, text="Welcome to TrackSmart AI", 
             style='Header.TLabel').pack(pady=(0,20))
             
    for title, content in sections.items():
        section_frame = ttk.LabelFrame(guide_frame, text=title, style='Section.TLabelframe')
        section_frame.pack(fill='x', pady=10, padx=5)
        ttk.Label(section_frame, text=content, 
                 style='Regular.TLabel',
                 wraplength=500).pack(pady=10, padx=10)
    
    ttk.Button(guide_frame, text="Close", 
              style='Secondary.TButton',
              command=guide_win.destroy).pack(pady=20)

def show_settings():
    settings_win = tk.Toplevel(root)
    settings_win.title("Settings")
    settings_win.geometry("300x400")
    
    def save_settings():
        theme = theme_var.get()
        auto_loc = auto_loc_var.get()
        cursor.execute("""
            UPDATE user_settings 
            SET theme = ?, auto_location = ?
            WHERE user_id = ?
        """, (theme, auto_loc, current_user_id))
        conn.commit()
        apply_theme(theme)
        settings_win.destroy()

    theme_var = tk.StringVar(value=current_theme)
    auto_loc_var = tk.BooleanVar()
    
    ttk.Label(settings_win, text="Theme:").pack(pady=5)
    ttk.Radiobutton(settings_win, text="Light", variable=theme_var, value="light").pack()
    ttk.Radiobutton(settings_win, text="Dark", variable=theme_var, value="dark").pack()
    
    ttk.Checkbutton(settings_win, text="Auto-detect location", variable=auto_loc_var).pack(pady=10)
    ttk.Button(settings_win, text="Save", command=save_settings).pack(pady=10)

# --- App Launch ---
def initialize_app():
    root.title("TrackSmart AI")
    
    # Set application icon
    icon_path = os.path.join(os.path.dirname(__file__), "assets", "icon.ico")
    if os.path.exists(icon_path):
        try:
            root.iconbitmap(icon_path)
        except tk.TclError:
            print("Could not load application icon")
    
    # Set initial window size and position
    width, height = map(int, WINDOW_SIZES['main'].split('x'))
    center_window(root, width, height)
    root.minsize(800, 600)
    
    # Initialize styles before showing any windows
    setup_styles()
    
    # Show login menu
    try:
        show_login_menu()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to start application: {str(e)}")
        root.quit()

if __name__ == "__main__":
    root = tk.Tk()
    initialize_app()
    root.mainloop()

# --- END ---
