# 📍 TrackSmart AI

### Intelligent Location Tracking & Personal Productivity Assistant

TrackSmart AI is a desktop application that combines location management, smart reminders, note-taking, geospatial visualization, and productivity tools into a single offline-first platform.

Built with Python, Tkinter, SQLite, and mapping technologies, TrackSmart AI helps users organize places, remember important events, analyze location history, and improve personal productivity through intelligent recommendations.

---

## Overview

TrackSmart AI is designed for users who frequently manage location-based information such as:

* Students tracking educational institutions and exam centers
* Travelers organizing destinations and travel notes
* Professionals managing client locations and appointments
* Individuals maintaining location-based reminders and personal records

The application stores all data locally using SQLite, providing a lightweight and privacy-focused experience without requiring cloud infrastructure.

---

## Key Features

### 📍 Smart Location Management

* Manual location logging
* Automatic location detection via IP
* Geocoding and reverse geocoding
* Location history tracking
* Searchable location records

### 📝 Notes & Reminders

* Attach notes to specific locations
* Create location-based reminders
* Edit and manage saved notes
* Tag-based organization system
* Reminder scheduling

### 🤖 AI-Powered Assistance

* Intelligent note categorization
* Context-aware productivity suggestions
* Smart tagging recommendations
* Time-based reminders and insights
* Future-ready architecture for LLM integration

### 🗺️ Interactive Mapping

* OpenStreetMap integration
* Folium-powered map visualization
* View saved locations on maps
* Geographic note visualization

### 📊 Analytics Dashboard

* Timeline view of activities
* Most visited locations
* Search and filtering tools
* Activity statistics
* Visual reports and charts

### 📦 Data Export

* Export location logs to CSV
* Export notes to JSON
* Backup and portability support

### 🔐 User Authentication

* User registration system
* Login and session management
* Password hashing
* Secure local authentication

### 🎨 User Experience

* Light mode and dark mode
* Modern Tkinter interface
* Responsive layouts
* Productivity-focused design

---

## Technology Stack

### Core Technologies

| Technology    | Purpose                 |
| ------------- | ----------------------- |
| Python 3.11   | Application Development |
| Tkinter + TTK | Desktop User Interface  |
| SQLite        | Local Database          |
| JSON          | Configuration & Export  |

### Location Services

| Technology    | Purpose            |
| ------------- | ------------------ |
| Folium        | Interactive Maps   |
| OpenStreetMap | Mapping Data       |
| Nominatim     | Geocoding Services |

### Analytics & Productivity

| Technology    | Purpose               |
| ------------- | --------------------- |
| CSV Export    | Data Portability      |
| JSON Export   | Structured Backups    |
| Rule-Based AI | Smart Recommendations |

---

## System Architecture

```text
User
 │
 ▼
TrackSmart AI Desktop Application
 │
 ├── Authentication Module
 ├── Location Management
 ├── Notes & Reminders
 ├── Analytics Engine
 ├── AI Assistant
 ├── Export Services
 │
 ▼
SQLite Database
 │
 ▼
Maps & Geolocation Services
(OpenStreetMap + Nominatim)
```

---

## Screenshots

Add screenshots to showcase:

### Dashboard

![Dashboard](assets/screenshots/dashboard.png)

### Location Tracking

![Tracking](assets/screenshots/tracking.png)

### Analytics Dashboard

![Analytics](assets/screenshots/stats.png)

### AI Suggestions

![AI Assistant](assets/screenshots/ai-assistant.png)

---

## Project Structure

```text
TrackSmart-AI/
│
├── assets/
│   ├── logo.png
│   ├── icon.ico
│   └── screenshots/
│
├── database/
│
├── main.py
├── requirements.txt
├── config.json
├── README.md
├── LICENSE
│
└── tracksmart.db
```

---

## Installation

### Clone Repository

```bash
git clone https://github.com/prakashgangurde-ux/TrackSmart-AI.git

cd TrackSmart-AI
```

### Create Virtual Environment

```bash
python -m venv venv
```

Activate environment:

Windows:

```bash
venv\Scripts\activate
```

Linux/macOS:

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Configuration

Create:

```json
{
  "WEATHER_API_KEY": "your_api_key",
  "DEFAULT_LOCATION": "Mumbai, India"
}
```

Place the file in the project root as:

```text
config.json
```

---

## Running the Application

```bash
python main.py
```

---

## Use Cases

### Students

* Save exam centers
* Track educational institutions
* Set study reminders

### Travelers

* Record visited locations
* Attach travel notes
* Build personal location journals

### Professionals

* Manage client locations
* Track meetings
* Organize location-based tasks

### Personal Productivity

* Location-linked reminders
* Smart note organization
* Activity tracking

---

## Future Enhancements

* GPT-powered conversational assistant
* Voice command integration
* Cloud synchronization
* Mobile companion application
* Push notifications
* Route planning
* Calendar integration
* Location prediction analytics

---

## Security & Privacy

* Local-first architecture
* SQLite-based storage
* Password hashing
* Session management
* No mandatory cloud dependency

---

## License

MIT License

Free for personal, educational, and commercial use.

---

## Author

Prakash Gangurde

GitHub:
https://github.com/prakashgangurde-ux

Building intelligent desktop applications with Python, AI, and geospatial technologies.

---

> Track locations, organize knowledge, and improve productivity with intelligent location-aware tools.
