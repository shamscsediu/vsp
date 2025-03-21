# Vulnerability Scanner Project (VSP)

A comprehensive web application security scanner that helps identify common vulnerabilities in websites. This tool performs automated security assessments to detect issues like XSS, SQL Injection, CSRF, insecure headers, and more.

## Features

- **Comprehensive Vulnerability Detection**: Scans for 10+ types of common web vulnerabilities
- **Detailed Reporting**: Provides severity ratings and remediation advice for each vulnerability
- **Real-time Progress Tracking**: Monitor scan progress in real-time
- **Asynchronous Processing**: Background processing of scans using Celery
- **Modern Tech Stack**: Built with Django, React, and Celery

## Vulnerabilities Detected

- Cross-Site Scripting (XSS)
- SQL Injection
- Cross-Site Request Forgery (CSRF)
- Missing Security Headers
- SSL/TLS Misconfigurations
- Clickjacking Vulnerabilities
- CORS Misconfigurations
- Sensitive Data Exposure
- Outdated Software/CMS Detection
- Open Redirect Vulnerabilities
- Insecure Cookie Settings
- Server Information Disclosure

## Tech Stack

- **Backend**: Django, Django REST Framework
- **Frontend**: React, Bootstrap
- **Task Queue**: Celery with Redis
- **Database**: PostgreSQL
- **Security Tools**: OWASP ZAP integration

## Prerequisites

- Python 3.8+
- Node.js 14+
- Redis
- PostgreSQL
- pip and npm

## Installation

### Backend Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/vsp.git
   cd vsp
2. Create and activate a virtual environment:
   
   ```bash
   python -m venv venv
   source venv/bin/activate
    ```
3. Install dependencies:
   
   ```bash
   cd backend
   pip install -r requirements.txt
    ```
4. Configure environment variables:
   
   - Copy the example .env file:
     ```bash
     cp .env.example .env
      ```
   - Edit the .env file with your database credentials and other settings
5. Set up the database:
   
   ```bash
   python manage.py migrate
    ```
6. Create a superuser (optional):
   
   ```bash
   python manage.py createsuperuser
    ```
### Frontend Setup
1. Install dependencies:
   ```bash
   cd ../frontend
   npm install
    ```
## Running the Application
### Start Redis (for Celery)
```bash
redis-server
 ```

### Start Celery Worker
```bash
cd backend
celery -A config worker --loglevel=info
 ```
```

### Start Backend Server
```bash
cd backend
python manage.py runserver
 ```

### Start Frontend Development Server
```bash
cd frontend
npm start
 ```

The application should now be running at:

- Frontend: http://localhost:3000
- Backend API: http://localhost:8000/api/
- Admin interface: http://localhost:8000/admin/
## Environment Variables
The backend uses environment variables for configuration. These are stored in a .env file in the backend directory. Here are the key variables:
 Variable Description Default DEBUG

Django debug mode

False SECRET_KEY

Django secret key

None ALLOWED_HOSTS

Comma-separated list of allowed hosts

localhost,127.0.0.1 DB_ENGINE

Database engine

django.db.backends.sqlite3 DB_NAME

Database name

db.sqlite3 DB_USER

Database user

None DB_PASSWORD

Database password

None DB_HOST

Database host

None DB_PORT

Database port

None REDIS_HOST

Redis host

localhost REDIS_PORT

Redis port

6379 REDIS_DB

Redis database number

0 CELERY_BROKER_URL

Celery broker URL

redis://localhost:6379/0 CELERY_RESULT_BACKEND

Celery result backend

redis://localhost:6379/0 CORS_ALLOWED_ORIGINS

Comma-separated list of allowed CORS origins

http://localhost:3000
## Usage
1. Navigate to the web interface at http://localhost:3000
2. Enter the URL of the website you want to scan
3. Click "Start Scan" and wait for the results
4. View detailed vulnerability information and remediation advice
## API Endpoints
- POST /api/scanner/start-scan/ : Start a new scan
- GET /api/scanner/scan-status/<scan_id>/ : Get scan status and results
- GET /api/scanner/vulnerability/<scan_id>/<vuln_id>/ : Get detailed vulnerability information
- POST /api/scanner/rescan/<scan_id>/ : Start a new scan of a previously scanned URL
- GET /api/scanner/compare/<scan_id1>/<scan_id2>/ : Compare results between two scans
## Project Structure
```plaintext
vsp/
├── backend/
│   ├── config/             # Django project settings
│   ├── scanner/            # Main scanner application
│   │   ├── models.py       # Database models
│   │   ├── serializers.py  # API serializers
│   │   ├── services.py     # Scanner implementation
│   │   ├── tasks.py        # Celery tasks
│   │   ├── urls.py         # API endpoints
│   │   └── views.py        # API views
│   ├── .env                # Environment variables
│   └── requirements.txt    # Python dependencies
├── frontend/
│   ├── public/             # Static files
│   ├── src/                # React source code
│   │   ├── components/     # UI components
│   │   ├── pages/          # Page components
│   │   ├── services/       # API services
│   │   └── App.js          # Main application
│   └── package.json        # Node.js dependencies
└── README.md               # This file
 ```
```

## Security Considerations
- This tool is designed for security professionals and website owners to test their own websites
- Always obtain proper authorization before scanning any website
- Some vulnerability checks may trigger security systems or cause unexpected behavior
- Use with caution on production systems
## Troubleshooting
### Common Issues
1. Redis Connection Error :
   
   - Ensure Redis server is running
   - Check Redis connection settings in .env file
2. Celery Worker Not Starting :
   
   - Verify Redis is running
   - Check for missing Python dependencies
   - Ensure the virtual environment is activated
3. Database Connection Issues :
   
   - Verify PostgreSQL is running
   - Check database credentials in .env file
   - Ensure the database exists
4. Scan Failures :
   
   - Check network connectivity to target website
   - Verify the URL format is correct
   - Some websites may block automated scanning tools
## Acknowledgements
- OWASP for security best practices and guidelines
- Django for the backend framework
- React for the frontend framework
- Celery for task queue management
## Disclaimer
This tool is meant for educational purposes and authorized security testing only. Always obtain proper permission before scanning any website. The developers are not responsible for any misuse of this tool.