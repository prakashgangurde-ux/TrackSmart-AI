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
|----------|----------|
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

### Prerequisites
- Python 3.11 or higher
- pip package manager
- Git (for cloning)

### 1. Clone & Setup
```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/TrackSmart-AI.git
cd TrackSmart-AI

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration
1. Create `config.json` in root directory:
```json
{
    "WEATHER_API_KEY": "your_api_key_here",
    "DEFAULT_LOCATION": "Mumbai, India"
}
```
2. Set up assets folder with icon.ico

### 3. Run the Application
```bash
python main.py
```

---

## 📸 Screenshots

### Main Dashboard
![Dashboard](assets/screenshots/dashboard.png)
*Main interface with location tracking and AI suggestions*

### Features Overview
| Feature | Screenshot |
|---------|------------|
| Location Tracking | ![Tracking](assets/screenshots/tracking.png) |
| AI Assistant | ![AI](assets/screenshots/ai-assistant.png) |
| Analytics | ![Stats](assets/screenshots/stats.png) |

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
**GitHub**: https://github.com/prakashgangurde-ux

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Coding Standards
- Follow PEP 8 guidelines
- Add docstrings for new functions
- Include type hints
- Write unit tests for new features

---

## 💡 Future Ideas
- GPT integration for smarter AI suggestions
- Voice notes or chat-style commands
- Firebase/Cloud sync
- Push notification reminders
- Android/Web extension

---

> "Track your world, enhance your memory, and simplify your life — with AI."
