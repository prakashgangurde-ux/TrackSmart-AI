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
WEATHER_API_KEY = ""  # Get from openweathermap.org

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
    """Enhanced AI suggestions based on user patterns and time context"""
    now = datetime.now()
    hour = now.hour
    weekday = now.strftime('%A')
    
    try:
        # Get user's location patterns
        cursor.execute("""
            SELECT location, COUNT(*) as visits,
                   strftime('%H', timestamp) as hour
            FROM locations 
            WHERE user_id = ?
            GROUP BY location, hour
            ORDER BY visits DESC
        """, (current_user_id,))
        patterns = cursor.fetchall()
        
        # Get recent reminders
        cursor.execute("""
            SELECT message FROM reminders 
            WHERE user_id = ? AND triggered = 0
            ORDER BY id DESC LIMIT 1
        """, (current_user_id,))
        pending_reminder = cursor.fetchone()
        
        suggestions = []
        
        # Time-based greeting
        if hour < 12:
            suggestions.append("Good morning!")
        elif hour < 18:
            suggestions.append("Good afternoon!")
        else:
            suggestions.append("Good evening!")
            
        # Location pattern suggestions
        if patterns:
            common_location = patterns[0][0]
            common_hour = int(patterns[0][2])
            if abs(hour - common_hour) <= 1:
                suggestions.append(f"You usually visit {common_location} around this time.")
        
        # Day-specific suggestions
        if weekday in ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday']:
            suggestions.append("Don't forget to check your work schedule.")
        elif weekday in ['Saturday', 'Sunday']:
            suggestions.append("It's the weekend! Time to relax or catch up on personal tasks.")
        
        # Weather-based suggestions
        try:
            cursor.execute("""
                SELECT location FROM locations 
                WHERE user_id = ? 
                ORDER BY timestamp DESC LIMIT 1
            """, (current_user_id,))
            last_location = cursor.fetchone()
            if last_location:
                weather = get_weather(last_location[0])
                if weather:
                    if weather['condition'].lower() in ['rain', 'snow', 'thunderstorm']:
                        suggestions.append(f"⚠️ {weather['condition']} expected. Plan indoor activities or carry an umbrella!")
                    elif weather['temp'] > 30:
                        suggestions.append("🌡️ It's very hot today. Stay hydrated!")
                    elif weather['temp'] < 10:
                        suggestions.append("🌡️ It's cold outside. Remember to dress warmly!")
        except Exception:
            pass
            
        # Reminder notifications
        if pending_reminder:
            suggestions.append(f"📌 Reminder: {pending_reminder[0]}")
        
        # Add productivity tips
        productivity_tips = [
            "💡 Take regular breaks to stay productive.",
            "💡 Consider updating your location reminders.",
            "💡 Review your travel patterns in the dashboard.",
            "💡 Keep your frequently visited locations marked for quick access."
        ]
        suggestions.append(random.choice(productivity_tips))
        
        return "\n\n".join(suggestions)
        
    except Exception as e:
        print(f"AI suggestion error: {e}")
        return "I'm here to help! Let me know if you need assistance."

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
    """Enhanced AI Assistant Window"""
    ai_win = tk.Toplevel(root)
    ai_win.title("AI Assistant")
    ai_win.geometry("450x600")
    center_window(ai_win, 450, 600)
    
    # Create main frame
    main_frame = ttk.Frame(ai_win)
    main_frame.pack(fill='both', expand=True, padx=20, pady=10)
    
    # Assistant header
    ttk.Label(main_frame, text="🤖 TrackSmart AI Assistant",
             style='Header.TLabel').pack(pady=10)
    
    # Suggestions area with scrolled text
    suggestions_frame = ttk.LabelFrame(main_frame, text="Personalized Suggestions")
    suggestions_frame.pack(fill='both', expand=True, pady=10)
    
    suggestions_text = tk.Text(suggestions_frame, wrap='word', height=10,
                             font=(STYLES['FONT_FAMILY'], 10))
    suggestions_text.pack(fill='both', expand=True, padx=10, pady=5)
    suggestions_text.insert('1.0', ai_suggestion())
    suggestions_text.config(state='disabled')
    
    # Quick Actions
    actions_frame = ttk.LabelFrame(main_frame, text="Quick Actions")
    actions_frame.pack(fill='x', pady=10)
    
    def refresh_suggestions():
        suggestions_text.config(state='normal')
        suggestions_text.delete('1.0', tk.END)
        suggestions_text.insert('1.0', ai_suggestion())
        suggestions_text.config(state='disabled')
    
    actions = [
        ("🔄 Refresh Suggestions", refresh_suggestions),
        ("📍 Quick Location Log", log_location),
        ("⚡ Auto-Detect Location", auto_log_location),
        ("🗺️ View Map", show_map_with_locations),
        ("📊 View Statistics", show_location_stats)
    ]
    
    # Create two columns for actions
    left_frame = ttk.Frame(actions_frame)
    left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
    right_frame = ttk.Frame(actions_frame)
    right_frame.pack(side='right', fill='both', expand=True, padx=5, pady=5)
    
    for i, (text, cmd) in enumerate(actions):
        frame = left_frame if i % 2 == 0 else right_frame
        ttk.Button(frame, text=text, command=cmd).pack(fill='x', pady=2)
    
    # Status bar
    status_frame = ttk.Frame(main_frame)
    status_frame.pack(fill='x', pady=5)
    
    # Get last activity
    cursor.execute("""
        SELECT location, timestamp 
        FROM locations 
        WHERE user_id = ? 
        ORDER BY timestamp DESC LIMIT 1
    """, (current_user_id,))
    last_activity = cursor.fetchone()
    
    if last_activity:
        status_text = f"Last location: {last_activity[0]}"
    else:
        status_text = "No recent activity"
        
    ttk.Label(status_frame, text=status_text,
             font=(STYLES['FONT_FAMILY'], 8)).pack(side='left')
    
    # Refresh button in status bar
    ttk.Button(status_frame, text="↻",
              width=3,
              command=refresh_suggestions).pack(side='right')
    
    # Auto-refresh suggestions every 5 minutes
    def auto_refresh():
        if ai_win.winfo_exists():
            refresh_suggestions()
            ai_win.after(300000, auto_refresh)  # 5 minutes
    
    ai_win.after(300000, auto_refresh)

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

    # Header with extra spacing and AI button
    header = ttk.Frame(main)
    header.pack(fill='x', pady=(0,20))
    
    # Left side of header
    header_left = ttk.Frame(header)
    header_left.pack(side='left', fill='x')
    ttk.Label(header_left, text="TrackSmart AI", 
             style='Header.TLabel').pack(side='left', pady=(0, 10))

    # Right side of header with buttons
    header_right = ttk.Frame(header)
    header_right.pack(side='right', fill='x')
    ttk.Button(header_right, text="🤖 AI Assistant", 
               style='MenuButton.TButton',
               command=open_ai_assistant).pack(side='left', padx=5, pady=10)
    ttk.Button(header_right, text="👋 Logout", 
               style='MenuButton.TButton',
               command=logout).pack(side='left', pady=10)

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

    # Tools Section with reorganized buttons
    tools_frame = ttk.LabelFrame(content, text="🛠️ Tools", style='Section.TLabelframe')
    tools_frame.grid(row=1, column=0, padx=5, pady=5, sticky='nsew')
    
    # Create two columns for tools
    tools_left = ttk.Frame(tools_frame)
    tools_left.pack(side='left', fill='both', expand=True, padx=2)
    tools_right = ttk.Frame(tools_frame)
    tools_right.pack(side='right', fill='both', expand=True, padx=2)
    
    # Left column buttons
    for btn_text, cmd in [
        ("Set Reminder", add_reminder),
        ("Manage Reminders", manage_reminders),
        ("Export to CSV", export_logs_to_csv),
        ("Convert GPS Logs", convert_gps_logs),
    ]:
        ttk.Button(tools_left, text=btn_text, style='MenuButton.TButton',
                  command=cmd).pack(padx=3, pady=3, fill='x')

    # Right column buttons
    for btn_text, cmd in [
        ("Enhanced Map", generate_enhanced_map),
        ("Live Location", setup_live_location),
        ("Route Planner", lambda: messagebox.showinfo("Coming Soon", "Route planning feature coming soon!")),
    ]:
        ttk.Button(tools_right, text=btn_text, style='MenuButton.TButton',
                  command=cmd).pack(padx=3, pady=3, fill='x')

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
    
    guide_frame = create_scrollable_frame(guide_win)
    
    sections = {
        "Getting Started": """
• Login or Register: Create an account to start using TrackSmart AI
• After logging in, you'll access the main dashboard with various features
• The interface is organized into sections: Location Tools, Analytics, Tools, and Settings
""",
        "AI Assistant": """
• Smart Suggestions: Get personalized recommendations based on your patterns
• Weather Integration: Receive weather-based activity suggestions
• Location Patterns: Learn about your frequently visited places
• Time-Aware: Contextual suggestions based on time of day and day of week
• Quick Actions: Access common functions directly from the AI Assistant
• Auto-Refresh: Suggestions update automatically every 5 minutes
""",
        "Location Tools": """
• Manual Log: Enter your current location manually
• Auto-Detect: Automatically detect location using IP geolocation
• Live Location: Real-time location tracking with movement detection
• Dashboard: Comprehensive view of your location history
• Enhanced Map: Interactive map with location markers and notes
• GPS Log Conversion: Convert raw GPS data to enriched location information
""",
        "Analytics & Reports": """
• Location Statistics: Visual graphs of your most visited places
• Activity Timeline: Chronological view of your movement patterns
• Search History: Find and filter specific location entries
• Export Options: Save data in CSV or JSON formats
• Custom Date Ranges: Generate reports for specific time periods
• Location Notes: Add and manage notes for specific locations
""",
        "Smart Features": """
• Location Reminders: Set location-based notifications
• Weather Updates: Real-time weather information for locations
• Pattern Recognition: Analysis of your movement habits
• Auto-Tracking: Optional automatic location logging
• Route Planning: Plan and optimize your travel routes
• Favorite Places: Mark and quickly access frequent locations
""",
        "Settings & Customization": """
• Theme Options: Switch between light and dark modes
• Notification Settings: Configure alert preferences
• Auto-Location: Enable/disable automatic detection
• Data Management: Export, backup, or clear your data
• Privacy Controls: Manage your location sharing preferences
• Profile Settings: Update your account information
""",
        "Tips & Best Practices": """
• Regular Updates: Keep your location log current for better insights
• Use Tags: Organize locations with meaningful tags
• Backup Data: Export your data periodically
• Check AI Suggestions: Get daily recommendations
• Review Timeline: Monitor your movement patterns
• Update Notes: Keep location notes current and relevant
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
    
    # Add version and support info
    info_frame = ttk.Frame(guide_frame)
    info_frame.pack(fill='x', pady=20)
    
    ttk.Label(info_frame, 
             text="Version 1.0 | For support: support@tracksmart.ai",
             style='Regular.TLabel').pack(side='left')
             
    ttk.Button(info_frame, text="Close",
              style='Secondary.TButton',
              command=guide_win.destroy).pack(side='right')

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
    
    # Set application icon using tracksmart_icon.ico
    icon_path = os.path.join(os.path.dirname(__file__), "assets", "tracksmart_icon.ico")
    if os.path.exists(icon_path):
        try:
            root.iconbitmap(icon_path)
        except tk.TclError as e:
            print(f"Could not load application icon: {e}")
            # Fallback to original icon if available
            fallback_icon = os.path.join(os.path.dirname(__file__), "assets", "icon.ico")
            if os.path.exists(fallback_icon):
                try:
                    root.iconbitmap(fallback_icon)
                except tk.TclError:
                    print("Could not load fallback icon")
    
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

def convert_gps_logs():
    """Convert raw GPS logs to enriched CSV with location names"""
    input_file = filedialog.askopenfilename(
        title="Select GPS Log File",
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
    )
    if not input_file:
        return

    output_file = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV files", "*.csv")],
        title="Save Enriched Location Data"
    )
    if not output_file:
        return

    try:
        geolocator = Nominatim(user_agent="tracksmart_ai")
        
        # Create progress window
        progress_win = tk.Toplevel()
        progress_win.title("Converting Logs")
        progress_label = ttk.Label(progress_win, text="Converting GPS logs...")
        progress_label.pack(pady=10)
        progress_bar = ttk.Progressbar(progress_win, mode='indeterminate')
        progress_bar.pack(pady=10, padx=20)
        progress_bar.start()

        with open(input_file, 'r', encoding='utf-8') as f, open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Date', 'Time', 'Latitude', 'Longitude', 'Location', 'Accuracy'])
            
            for line in f:
                # Expected format: "YYYY-MM-DD HH:MM:SS,LAT,LON"
                try:
                    datetime_str, lat, lon = line.strip().split(',')
                    date, time = datetime_str.split(' ')
                    lat, lon = float(lat), float(lon)
                    
                    # Reverse geocoding with error handling
                    try:
                        location = geolocator.reverse(f"{lat}, {lon}", timeout=10)
                        location_name = location.address if location else "Unknown"
                        accuracy = location.raw.get('importance', 'N/A') if location else 'N/A'
                    except GeocoderTimedOut:
                        location_name = "Geocoding Timeout"
                        accuracy = 'N/A'
                    except Exception as e:
                        location_name = f"Geocoding Error: {str(e)}"
                        accuracy = 'N/A'
                    
                    writer.writerow([date, time, lat, lon, location_name, accuracy])
                    progress_win.update()
                    
                except (ValueError, IndexError):
                    continue

        progress_win.destroy()
        messagebox.showinfo("Success", "GPS logs converted successfully!")
    
    except Exception as e:
        if 'progress_win' in locals():
            progress_win.destroy()
        messagebox.showerror("Error", f"Failed to convert logs: {str(e)}")

def generate_enhanced_map():
    """Generate an interactive map with location history and notes"""
    if not current_user_id:
        messagebox.showerror("Error", "Please login first!")
        return
        
    try:
        # Fetch all locations with notes
        cursor.execute("""
            SELECT l.location, l.latitude, l.longitude, 
                   GROUP_CONCAT(IFNULL(n.note, ''), '|') as notes,
                   IFNULL(m.color, 'red') as color
            FROM locations l
            LEFT JOIN location_notes n ON l.location = n.location 
                AND l.user_id = n.user_id
            LEFT JOIN marked_locations m ON l.location = m.location 
                AND l.user_id = m.user_id
            WHERE l.user_id = ? AND l.latitude IS NOT NULL
            GROUP BY l.location, l.latitude, l.longitude
        """, (current_user_id,))
        
        locations = cursor.fetchall()
        
        if not locations:
            messagebox.showinfo("Map", "No location data available")
            return
            
        # Create map centered on first location
        center_lat = sum(loc[1] for loc in locations if loc[1]) / len(locations)
        center_lon = sum(loc[2] for loc in locations if loc[2]) / len(locations)
        m = folium.Map(location=[center_lat, center_lon], zoom_start=10)
        
        # Add locations with popups containing notes
        for loc_name, lat, lon, notes, color in locations:
            if lat and lon:
                popup_html = f"<b>{loc_name}</b><br>"
                if notes and notes != '|':
                    popup_html += "<br>".join(filter(None, notes.split("|")))
                
                folium.Marker(
                    location=[lat, lon],
                    popup=folium.Popup(popup_html, max_width=300),
                    icon=folium.Icon(color=color or 'red')
                ).add_to(m)
        
        # Save and open the map
        map_file = os.path.join(os.path.dirname(__file__), "location_map.html")
        m.save(map_file)
        webbrowser.open('file://' + os.path.abspath(map_file))
        
    except Exception as e:
        messagebox.showerror("Error", f"Failed to generate map: {str(e)}")

def setup_live_location():
    """Create and open live location detector page"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Live Location Detector</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body { 
                font-family: Arial; 
                padding: 20px;
                max-width: 800px;
                margin: 0 auto;
                background: #f5f5f5;
            }
            #location { 
                margin: 20px 0; 
                padding: 15px;
                background: white;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            button { 
                padding: 12px 20px;
                margin: 5px;
                border: none;
                border-radius: 4px;
                background: #2962ff;
                color: white;
                cursor: pointer;
                transition: background 0.3s;
            }
            button:hover {
                background: #1565c0;
            }
            .error {
                color: #d32f2f;
                padding: 10px;
                background: #ffebee;
                border-radius: 4px;
            }
            .coords {
                font-family: monospace;
                font-size: 1.1em;
            }
        </style>
    </head>
    <body>
        <h2>Live Location Detector</h2>
        <div id="location">Waiting for location...</div>
        <button onclick="getLocation()">Update Location</button>
        <button onclick="sendToApp()">Send to TrackSmart</button>
        <button onclick="startTracking()">Start Tracking</button>
        <button onclick="stopTracking()" style="display:none;" id="stopBtn">Stop Tracking</button>
        
        <script>
        let watchId = null;
        let lastPosition = null;
        const MIN_DISTANCE = 10; // meters
        
        function getLocation() {
            if (navigator.geolocation) {
                document.getElementById("location").innerHTML = "Getting location...";
                navigator.geolocation.getCurrentPosition(showPosition, showError, {
                    enableHighAccuracy: true,
                    timeout: 10000,
                    maximumAge: 0
                });
            } else {
                document.getElementById("location").innerHTML = 
                    '<div class="error">Geolocation not supported</div>';
            }
        }
        
        function startTracking() {
            if (navigator.geolocation) {
                watchId = navigator.geolocation.watchPosition(showPosition, showError, {
                    enableHighAccuracy: true,
                    timeout: 10000,
                    maximumAge: 0
                });
                document.getElementById("stopBtn").style.display = "inline";
            }
        }
        
        function stopTracking() {
            if (watchId !== null) {
                navigator.geolocation.clearWatch(watchId);
                watchId = null;
                document.getElementById("stopBtn").style.display = "none";
            }
        }
        
        function showPosition(position) {
            const lat = position.coords.latitude;
            const lon = position.coords.longitude;
            const accuracy = position.coords.accuracy;
            const timestamp = new Date(position.timestamp).toLocaleString();
            
            document.getElementById("location").innerHTML = 
                `<div class="coords">
                    Latitude: ${lat.toFixed(6)}<br>
                    Longitude: ${lon.toFixed(6)}<br>
                    Accuracy: ${accuracy.toFixed(1)}m<br>
                    Time: ${timestamp}
                </div>`;
            
            window.currentPosition = {lat, lon, accuracy, timestamp};
            
            // Auto-send if significant movement detected
            if (lastPosition && calculateDistance(lastPosition, {lat, lon}) > MIN_DISTANCE) {
                sendToApp();
            }
            lastPosition = {lat, lon};
        }
        
        function showError(error) {
            let message = "Location error: ";
            switch(error.code) {
                case error.PERMISSION_DENIED:
                    message += "Permission denied";
                    break;
                case error.POSITION_UNAVAILABLE:
                    message += "Position unavailable";
                    break;
                case error.TIMEOUT:
                    message += "Request timeout";
                    break;
                default:
                    message += "Unknown error";
                    break;
            }
            document.getElementById("location").innerHTML = 
                `<div class="error">${message}</div>`;
        }
        
        function calculateDistance(pos1, pos2) {
            const R = 6371e3; // Earth's radius in meters
            const φ1 = pos1.lat * Math.PI/180;
            const φ2 = pos2.lat * Math.PI/180;
            const Δφ = (pos2.lat-pos1.lat) * Math.PI/180;
            const Δλ = (pos2.lon-pos1.lon) * Math.PI/180;
            const a = Math.sin(Δφ/2) * Math.sin(Δφ/2) +
                      Math.cos(φ1) * Math.cos(φ2) *
                      Math.sin(Δλ/2) * Math.sin(Δλ/2);
            const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
            return R * c; // in meters
        }
        
        function sendToApp() {
            if (window.currentPosition) {
                const url = `tracksmart://location?` +
                    `lat=${window.currentPosition.lat}&` +
                    `lon=${window.currentPosition.lon}&` +
                    `accuracy=${window.currentPosition.accuracy}&` +
                    `time=${encodeURIComponent(window.currentPosition.timestamp)}`;
                window.location.href = url;
            } else {
                alert("No location available yet");
            }
        }
        
        // Get initial location
        getLocation();
        </script>
    </body>
    </html>
    """
    
    # Save and open the HTML file with UTF-8 encoding
    try:
        html_file = os.path.join(os.path.dirname(__file__), "live_location.html")
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        webbrowser.open(html_file)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to create live location page: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    initialize_app()
    root.mainloop()

# --- END ---
