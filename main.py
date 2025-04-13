# TrackSmart AI – Tkinter Desktop Version
# Author: You + ChatGPT
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

def apply_theme(theme_name):
    global current_theme
    current_theme = theme_name
    style = ttk.Style()
    if theme_name == "dark":
        root.configure(bg='#2b2b2b')
        style.configure("TLabel", background='#2b2b2b', foreground='white')
        style.configure("TButton", background='#404040', foreground='white')
    else:
        root.configure(bg='#f0f0f0')
        style.configure("TLabel", background='#f0f0f0', foreground='black')
        style.configure("TButton", background='#e0e0e0', foreground='black')

# --- Authentication ---
def register():
    global current_user_id
    reg_win = tk.Toplevel(root)
    reg_win.title("Register")
    reg_win.geometry("300x200")

    def do_register():
        username = user_entry.get()
        password = pass_entry.get()
        email = email_entry.get()
        
        if len(username) < 3 or len(password) < 6:
            messagebox.showerror("Error", "Username must be at least 3 characters and password at least 6 characters")
            return
            
        if not validate_email(email):
            messagebox.showerror("Error", "Invalid email format")
            return
            
        try:
            hashed_pwd = hash_password(password)
            cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", 
                         (username, hashed_pwd, email))
            cursor.execute("INSERT INTO user_settings (user_id) VALUES (?)", 
                         (cursor.lastrowid,))
            conn.commit()
            messagebox.showinfo("Success", "Registration complete")
            reg_win.destroy()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists")

    tk.Label(reg_win, text="Username:").pack()
    user_entry = tk.Entry(reg_win)
    user_entry.pack()
    user_entry.focus()

    tk.Label(reg_win, text="Password:").pack()
    pass_entry = tk.Entry(reg_win, show="*")
    pass_entry.pack()

    tk.Label(reg_win, text="Email:").pack()
    email_entry = tk.Entry(reg_win)
    email_entry.pack()

    tk.Button(reg_win, text="Register", command=do_register).pack(pady=10)

def login():
    global current_user_id
    login_win = tk.Toplevel(root)
    login_win.title("Login")
    login_win.geometry("300x200")

    def do_login():
        global current_user_id, session_start
        username = user_entry.get()
        password = pass_entry.get()
        hashed_pwd = hash_password(password)
        
        try:
            cursor.execute("""
                SELECT users.id, user_settings.theme 
                FROM users 
                LEFT JOIN user_settings ON users.id = user_settings.user_id 
                WHERE username = ? AND password = ?
            """, (username, hashed_pwd))
            result = cursor.fetchone()
            
            if result:
                current_user_id = result[0]
                session_start = datetime.now()
                cursor.execute("UPDATE settings SET last_login = ? WHERE user_id = ?", 
                             (session_start.strftime("%Y-%m-%d %H:%M:%S"), current_user_id))
                conn.commit()
                apply_theme(result[1] if result[1] else 'light')
                show_main_menu()
                login_win.destroy()
            else:
                messagebox.showerror("Error", "Invalid credentials")
        except Exception as e:
            messagebox.showerror("Error", f"Login failed: {str(e)}")

    tk.Label(login_win, text="Username:").pack()
    user_entry = tk.Entry(login_win)
    user_entry.pack()
    user_entry.focus()

    tk.Label(login_win, text="Password:").pack()
    pass_entry = tk.Entry(login_win, show="*")
    pass_entry.pack()

    tk.Button(login_win, text="Login", command=do_login).pack(pady=10)

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

    cursor.execute("SELECT location, timestamp FROM locations WHERE user_id = ?", (current_user_id,))
    rows = cursor.fetchall()

    if not rows:
        messagebox.showinfo("Export", "No location data to export.")
        return

    with open("tracksmart_logs.csv", mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["Location", "Timestamp"])
        for loc, ts in rows:
            writer.writerow([loc, ts])

    messagebox.showinfo("Export Complete", "Location logs exported to 'tracksmart_logs.csv'.")

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

    # Fetch existing notes
    cursor.execute("""
        SELECT id, note, timestamp 
        FROM location_notes 
        WHERE user_id = ? AND location = ?
        ORDER BY timestamp DESC
    """, (current_user_id, location))
    
    notes_frame = ttk.Frame(notes_win)
    notes_frame.pack(fill='both', expand=True, padx=10, pady=5)

    # Add note section
    ttk.Label(notes_frame, text="Add New Note:").pack(pady=5)
    note_entry = ttk.Entry(notes_frame, width=40)
    note_entry.pack(pady=5)

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

    # Increase window size
    root.geometry("600x700")  

    label = ttk.Label(root, text="TrackSmart AI – Main Menu", font=("Arial", 16))
    label.pack(pady=10)

    # Create notebook for tabs
    notebook = ttk.Notebook(root)
    notebook.pack(fill='both', expand=True, padx=10, pady=5)

    # Create tabs
    locations_tab = ttk.Frame(notebook)
    reminders_tab = ttk.Frame(notebook)
    tools_tab = ttk.Frame(notebook)
    settings_tab = ttk.Frame(notebook)

    notebook.add(locations_tab, text="📍 Locations")
    notebook.add(reminders_tab, text="⏰ Reminders")
    notebook.add(tools_tab, text="🛠️ Tools")
    notebook.add(settings_tab, text="⚙️ Settings")

    # Locations tab
    ttk.Button(locations_tab, text="📍 Log Location (Manual)", width=30, command=log_location).pack(pady=5)
    ttk.Button(locations_tab, text="🌍 Auto-Detect Location", width=30, command=auto_log_location).pack(pady=5)
    ttk.Button(locations_tab, text="📊 View Dashboard", width=30, command=show_dashboard).pack(pady=5)
    ttk.Button(locations_tab, text="📈 View Location Stats", width=30, command=show_location_stats).pack(pady=5)
    ttk.Button(locations_tab, text="🗺️ View Map with Locations", width=30, command=show_map_with_locations).pack(pady=5)
    ttk.Button(locations_tab, text="🔍 Search History", width=30, command=search_location_history).pack(pady=5)

    # Reminders tab
    ttk.Button(reminders_tab, text="⏰ Set Location Reminder", width=30, command=add_reminder).pack(pady=5)
    ttk.Button(reminders_tab, text="🧹 Manage Reminders", width=30, command=manage_reminders).pack(pady=5)

    # Tools tab
    ttk.Button(tools_tab, text="🤖 AI Assistant", width=30, command=open_ai_assistant).pack(pady=5)
    ttk.Button(tools_tab, text="💾 Export Data", width=30, command=export_data).pack(pady=5)
    ttk.Button(tools_tab, text="📦 Export Logs to CSV", width=30, command=export_logs_to_csv).pack(pady=5)
    ttk.Button(tools_tab, text="📅 Activity Timeline", width=30, command=show_activity_timeline).pack(pady=5)
    ttk.Button(tools_tab, text="🗑️ Clear All Data", width=30, command=clear_all_data).pack(pady=5)

    # Settings tab
    ttk.Button(settings_tab, text="⚙️ Settings", width=30, command=show_settings).pack(pady=5)
    ttk.Button(settings_tab, text="🌓 Toggle Theme", width=30, command=toggle_theme).pack(pady=5)

    # Logout button remains outside tabs
    ttk.Button(root, text="👋 Logout", width=30, command=logout).pack(pady=10)
    ttk.Label(root, text="Made with Python + AI + SQLite", font=("Arial", 10)).pack(side="bottom", pady=10)

def show_login_menu():
    for widget in root.winfo_children():
        widget.destroy()

    label = ttk.Label(root, text="Welcome to TrackSmart AI", font=("Arial", 16))
    label.pack(pady=20)

    ttk.Button(root, text="🔐 Login", width=30, command=login).pack(pady=10)
    ttk.Button(root, text="🆕 Register", width=30, command=register).pack(pady=10)

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
root = tk.Tk()
root.title("TrackSmart AI – Login")
root.geometry("600x700")
show_login_menu()

root.mainloop()

# --- END ---
