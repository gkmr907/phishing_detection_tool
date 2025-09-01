# 🔎 Phishing Detection Tool
### _"Your intelligent scanner for a safer web."_

A lightweight web-based tool to analyze suspicious URLs and classify them as **Safe, Suspicious, or Malicious**
Built with a focus on **cybersecurity awareness, simplicity, and practical use cases**.


## 🚀 Features
- Real-time URL analysis with a powerful rule-based engine:
  - Detection of IP-based URLs and non-HTTPS links 
  - Analysis of suspicious keywords (e.g., *login, verify*) 
  - Checks for suspicious TLDs (`.tk`, `.xyz`, etc.) and long domain names
  - Real-time checks for URL redirection and domain age 
- **Two-Score Risk Analysis** with a **Safe / Suspicious / Malicious** verdict 
- User-friendly frontend with clear, educational reasons for risks
- Clean API integration between frontend and backend


## 🛠️ Tech Stack
- **Backend:** Python (Flask) 
- **Web Server:** Flask's built-in development server
- **Frontend:** HTML, CSS, JavaScript
- **Key Libraries:** `tldextract`, `whois`, `requests` 
- **Version Control:** Git & GitHub 

## 📂 Project Structure
```bash
PHISHING_DETECTION_TOOL/
├── backend/ # Python Flask backend
│   ├── app.py                  # The Flask application (API)
│   ├── phishing_model.py         # All rule-based detection logic
│   └── requirements.txt          # Python dependencies
├── frontend/                 # HTML + CSS + JS frontend
│   ├── index.html              # The main web page
│   ├── script.js               # The frontend logic
│   └── style.css               # The styling for the UI
├── venv/                       # Your Python virtual environment
│   ├── Include/
│   ├── Lib/
│   ├── Scripts/
│   └── pyvenv.cfg              # Virtual environment configuration
└── .gitignore                  # Tells Git to ignore the venv folder
```

## ⚙️ How to Run the Project
1.  **Clone the Repository:**
    ```
    git clone [https://github.com/your-github-user/phishing_detection_tool.git](https://github.com/your-github-user/phishing_detection_tool.git)
    cd phishing_detection_tool
    ```
2.  **Set up the Backend:**
    * Create a virtual environment: `python -m venv venv`
    * Activate it: `venv\Scripts\activate` (Windows) or `source venv/bin/bin/activate` (Mac/Linux)
    * Install dependencies: `pip install -r backend/requirements.txt`
3.  **Start the Backend Server:**
    ```
    flask --app backend/app.py run
    ```
4.  **Open the Frontend:**
    * Open your browser.
    * Navigate to the `frontend` folder and double-click `index.html` to open the tool.
    * 


## 🎯 Future Enhancements
- Hybrid Machine Learning System: Integrate the current rule-based system with a machine learning model. The tool can use rules for an initial, fast check for obvious threats and then pass more complex URLs to the ML model for a deeper analysis.
- Browser Extension: Develop a simple browser extension that runs the tool's checks automatically on every URL, providing a real-time safety indicator to the user.
- Email Scanning: Extend detection to analyze email content and attachments.
- Multi-Language and Global Threat Detection: Expand the tool's keyword list to support other languages and integrate with external APIs to check for threats globally.




