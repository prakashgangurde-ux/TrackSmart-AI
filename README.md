# 📍 TrackSmart AI
### Smart Location-Based Assistant

---

> A modern Python desktop application for intelligent location tracking, notes, reminders, AI-powered suggestions, geolocation mapping, and personal productivity.

---

## 🎯 Overview
**TrackSmart AI** is a powerful offline desktop app built using Python and Tkinter, integrating AI-powered features with smart location-based logging, reminders, notes, weather updates, and map visualization — all backed by SQLite.

Whether you're a student tracking exam centers, a traveler logging favorite places, or someone who needs intelligent reminders — **TrackSmart is your personal smart map assistant**.

---

## 🚀 Features

| Category | Features |
|---------|----------|
| 📍 Location | Manual log, auto-detect via IP, geocoding, history |
| 📝 Notes & Reminders | Save notes to location, tag-based filtering, edit/delete reminders |
| 🤖 AI Assistant | Time-aware tips, smart tagging for notes |
| 📊 Dashboard | Timeline view, top visited stats (graphs), searchable logs |
| 🗺️ Map Tools | View notes & places on map (folium + OpenStreetMap) |
| 📦 Export | Export logs to CSV, notes to JSON |
| 🔐 User Management | Register/Login system with session tracking and password hashing |
| 🎨 Theming | Toggle between light/dark mode for better UX |

---

## 🛠 Tech Stack

- **Language**: Python 3.11
- **GUI**: Tkinter + TTK (modern layout)
- **DB**: SQLite (local database)
- **AI**: Smart rule-based logic (GPT-ready)
- **Map**: Folium + OpenStreetMap + Nominatim (for geocoding)
- **Export**: CSV / JSON

---

## 🧪 Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/TrackSmart-AI.git
cd TrackSmart-AI
```

### 2. Install Requirements
```bash
pip install -r requirements.txt
```
> Requirements include: `folium`, `requests`, `matplotlib`, `pillow`

### 3. Run the App
```bash
python main.py
```

---

## 📸 Screenshots
Screenshots are stored in [assets/screenshots/](assets/screenshots/)

---

## 📁 Folder Structure
```
TrackSmart-AI/
├── assets/
│   ├── logo.png
│   ├── icon.ico
├── main.py
├── requirements.txt
├── README.md
├── tracksmart.db (auto-generated)
```

---

## 📄 License
MIT License – free for personal, educational, or commercial use with attribution.

---

## 👨‍💻 Author
**Name**: PRAKASH GANGURDE  
**Institution**: BCA, 2025  
**GitHub**: https://github.com/YOUR_USERNAME

---

## 💡 Future Ideas
- GPT integration for smarter AI suggestions
- Voice notes or chat-style commands
- Firebase/Cloud sync
- Push notification reminders
- Android/Web extension

---

> "Track your world, enhance your memory, and simplify your life — with AI."