# Salamander - Text Humanizer

Salamander is a Flask-based web application that transforms AI-generated text into natural, human-like writing using advanced NLP models. It supports user authentication via Firebase, text humanization, history tracking, payment integration, and admin management, with a responsive UI built using Tailwind CSS and Font Awesome.

## Features

- **Text Humanization**: Paraphrases AI-generated text to sound natural while preserving meaning.
- **Ultra Mode**: Premium feature with advanced NLP humanization techniques.
- **User Authentication**: Google sign-in via Firebase Authentication.
- **History Tracking**: Save, search, and manage past humanization sessions with view, copy, and delete functionality.
- **Admin Management**: CLI tools to create, delete, and list admin users.
- **Payment Integration**: Supports eSewa and Khalti for premium subscriptions.
- **Rate Limiting**: Prevents API abuse using `billing/rate_limiter.py`.
- **Database**: Uses SQLAlchemy with PostgreSQL (production) or SQLite (development), managed with Flask-Migrate.
- **Responsive UI**: Mobile-friendly interface with Tailwind CSS and Font Awesome.

## Project Structure

```
humanizer_app/
├── api.py                  # API routes for humanization and history
├── app.py                  # Main Flask application
├── config.py               # Configuration settings
├── auth/                   # Authentication logic
│   └── firebase_auth.py    # Firebase authentication handlers
├── billing/                # Billing and rate limiting
│   ├── billing_service.py  # Billing logic
│   ├── rate_limiter.py     # API rate limiting
│   └── sanitize.py         # Input sanitization
├── config/                 # Configuration files
│   └── salamanders-122ec-firebase-adminsdk-fbsvc-8c226bb171.json  # Firebase service account
├── core/                   # Core application logic
│   ├── admin/              # Admin management
│   │   ├── admin_setup.py  # Admin initialization
│   │   ├── cli.py          # CLI for admin management
│   │   ├── config.py       # Admin configuration
│   │   ├── models.py       # Admin models
│   │   ├── utils.py        # Admin utilities
│   │   └── views.py        # Admin views
│   ├── analytics/          # Analytics (if implemented)
│   ├── decorators.py       # Custom decorators
│   └── exports.py          # Export utilities
├── database/               # Database operations
│   ├── db_handler.py       # SQLAlchemy database handler
│   ├── firebase_handler.py # Firebase database operations
│   └── repository.py       # Data repository patterns
├── models/                 # Data models
│   ├── abstracts.py        # Abstract base models
│   └── domain.py           # Domain-specific models
├── payment/                # Payment processing
│   ├── esewa_adapter.py    # eSewa payment adapter
│   ├── khalti_adapter.py   # Khalti payment adapter
│   ├── handler.py          # Payment handlers
│   ├── helper.py           # Payment utilities
│   └── payment_adapter.py  # Payment adapter interface
├── processor/              # Text processing logic
│   └── humanizer.py        # Humanization logic
├── service/                # Business logic services
│   ├── humanizer_service.py # Humanization service
│   └── service.py          # Base service class
├── static/                 # Static assets (CSS, JS)
│   ├── css/
│   └── js/
├── templates/              # HTML templates
│   ├── admin/              # Admin dashboard templates
│   ├── dashboard.html       # Main application interface
│   ├── error.html          # Error page
│   ├── login.html          # Login page
│   ├── payment.html        # Payment page
│   ├── payment_success.html # Payment success page
│   └── payment_failure.html # Payment failure page
├── utils/                  # Utility functions
│   ├── decorators.py       # Utility decorators
│   └── logger.py           # Logging utilities
├── db.sqlite3              # SQLite database (development)
├── identifier.sqlite       # Additional SQLite database (if used)
├── docker-compose.yml      # Docker Compose configuration
├── Dockerfile              # Docker configuration
├── error.log               # Application error logs
├── instance/               # Flask instance folder
├── migrations/             # Flask-Migrate database migrations
├── requirements.txt        # Python dependencies
└── venv/                   # Virtual environment
```

## Prerequisites

- Python 3.8+
- PostgreSQL 12+ (for production; SQLite for development)
- Flask
- SQLAlchemy
- Flask-Migrate
- Firebase Admin SDK
- Transformers
- PyTorch
- Docker (optional, for containerized deployment)

## Installation

1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   cd humanizer_app
   ```

2. **Set Up Virtual Environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   Ensure `requirements.txt` includes all packages listed in the Requirements section below.

4. **Configure Firebase**:
   - Create a Firebase project at [Firebase Console](https://console.firebase.google.com/).
   - Enable Google authentication and Firestore (if used).
   - Create a service account, download the JSON key, and place it in `config/` (e.g., `salamanders-122ec-firebase-adminsdk-fbsvc-8c226bb171.json`).
   - Update `config.py` with Firebase credentials, database URI, and other settings (e.g., `SECRET_KEY`).

5. **Set Up PostgreSQL (Production)**:
   - Install PostgreSQL and create a database:
     ```bash
     sudo apt-get install postgresql postgresql-contrib  # On Ubuntu
     psql -U postgres -c "CREATE DATABASE salamander_db;"
     ```
   - Update `config.py` with the PostgreSQL URI:
     ```python
     SQLALCHEMY_DATABASE_URI = 'postgresql://username:password@localhost:5432/salamander_db'
     ```

6. **Initialize the Database**:
   - For SQLite (development):
     ```bash
     flask db init
     flask db migrate
     flask db upgrade
     ```
   - For PostgreSQL (production), ensure the URI is set, then run the same commands.

7. **Set Up Admin User**:
   Create an admin user using the CLI:
   ```bash
   flask create-admin --username <username> --email <email> --password <password> --role admin
   ```

## Running the Application

1. **Activate Virtual Environment**:
   ```bash
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Run the Application**:
   ```bash
   flask run
   ```
   Or:
   ```bash
   python app.py
   ```
   The application will be available at `http://localhost:5000`.

## Admin CLI Commands

Manage admin users via the command line:

- **Create Admin**:
  ```bash
  flask create-admin --username <username> --email <email> --password <password> --role <admin|super_admin>
  ```

- **Delete Admin**:
  ```bash
  flask delete-admin --username <username>
  ```

- **List Admins**:
  ```bash
  flask list-admins
  ```

## Development

### Adding New Features

1. Create a feature branch:
   ```bash
   git checkout -b feature/<feature-name>
   ```
2. Implement the feature in the appropriate module (e.g., `service/`, `core/`).
3. Add tests in a `tests/` directory (create if needed).
4. Submit a pull request.

### Running Tests

```bash
pytest
```
*Note*: If a `tests/` directory doesn’t exist, create one and add test cases for key components (e.g., `humanizer_service.py`, `billing_service.py`).

### Database Migrations

To update the database schema:
```bash
flask db migrate -m "Description of changes"
flask db upgrade
```

## Deployment

For production:

1. **Set Environment Variables**:
   - `FLASK_ENV=production`
   - `SECRET_KEY=<your-secret-key>`
   - `SQLALCHEMY_DATABASE_URI=postgresql://username:password@host:port/salamander_db`
   - Firebase credentials (via `config.py` or environment variables)

2. **Use a Production Server**:
   ```bash
   gunicorn -w 4 -b 0.0.0.0:5000 app:app
   ```

3. **Apply Migrations**:
   ```bash
   flask db upgrade
   ```

4. **Docker (Optional)**:
   ```bash
   docker-compose up --build
   ```

5. **Enable HTTPS**:
   - Use a reverse proxy (e.g., Nginx) with SSL certificates from Let’s Encrypt.

## Requirements

The following packages are required (as listed in your input):

- aiohappyeyeballs==2.6.1
- aiohttp==3.11.18
- aiosignal==1.3.2
- alembic==1.15.2
- analytics-python==1.4.post1
- annotated-types==0.7.0
- anyio==4.9.0
- async-timeout==5.0.1
- attrs==25.3.0
- backoff==1.10.0
- bcrypt==4.3.0
- blinker==1.9.0
- CacheControl==0.14.2
- cachetools==5.5.2
- certifi==2025.4.26
- cffi==1.17.1
- charset-normalizer==2.0.12
- click==8.1.8
- contourpy==1.3.0
- cryptography==44.0.2
- cycler==0.12.1
- et_xmlfile==2.0.0
- exceptiongroup==1.2.2
- fastapi==0.115.12
- ffmpy==0.5.0
- firebase-admin==5.0.3
- Flask==3.1.1
- Flask-Migrate==4.1.0
- Flask-SQLAlchemy==3.1.1
- Flask-WTF==1.2.2
- fonttools==4.57.0
- frozenlist==1.6.0
- gcloud==0.18.3
- git-filter-repo==2.47.0
- google-api-core==2.24.2
- google-api-python-client==2.168.0
- google-auth==2.39.0
- google-auth-httplib2==0.2.0
- google-cloud-core==2.4.3
- google-cloud-firestore==2.20.2
- google-cloud-storage==3.1.0
- google-crc32c==1.7.1
- google-resumable-media==2.7.2
- googleapis-common-protos==1.70.0
- gradio==2.8.0
- greenlet==3.2.2
- grpcio==1.71.0
- grpcio-status==1.71.0
- h11==0.16.0
- httpcore==1.0.9
- httplib2==0.22.0
- httpx==0.28.1
- idna==3.10
- importlib_metadata==8.7.0
- importlib_resources==6.5.2
- itsdangerous==2.2.0
- Jinja2==3.1.6
- jwcrypto==1.5.6
- kiwisolver==1.4.7
- linkify-it-py==2.0.3
- Mako==1.3.10
- markdown-it-py==3.0.0
- MarkupSafe==3.0.2
- matplotlib==3.9.4
- mdit-py-plugins==0.4.2
- mdurl==0.1.2
- monotonic==1.6
- msgpack==1.1.0
- multidict==6.4.3
- numpy==2.0.2
- oauth2client==4.1.3
- openpyxl==3.1.5
- packaging==25.0
- pandas==2.2.3
- paramiko==3.5.1
- pillow==11.2.1
- propcache==0.3.1
- proto-plus==1.26.1
- protobuf==5.29.4
- psycopg2-binary==2.9.10
- pyasn1==0.6.1
- pyasn1_modules==0.4.2
- pycparser==2.22
- pycryptodome==3.22.0
- pydantic==2.11.3
- pydantic_core==2.33.1
- pydub==0.25.1
- pymongo==4.0.1
- PyNaCl==1.5.0
- pyparsing==3.2.3
- Pyrebase4==4.7.1
- python-dateutil==2.9.0.post0
- python-dotenv==1.0.1
- python-jwt==4.1.0
- python-multipart==0.0.20
- pytz==2025.2
- redis==6.1.0
- requests==2.26.0
- requests-toolbelt==0.10.1
- rsa==4.9.1
- six==1.17.0
- sniffio==1.3.1
- SQLAlchemy==2.0.41
- starlette==0.46.2
- typing-inspection==0.4.0
- typing_extensions==4.13.2
- tzdata==2025.2
- uc-micro-py==1.0.3
- uritemplate==4.1.1
- urllib3==1.26.20
- uvicorn==0.34.2
- Werkzeug==3.1.3
- WTForms==3.2.1
- yarl==1.20.0
- zipp==3.21.0

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contributing

Contributions are welcome! Please:
1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/<feature-name>`.
3. Submit a pull request with clear descriptions and tests.

## Notes
- Ensure the Firebase service account JSON is excluded from version control (add `config/*.json` to `.gitignore`).
- Use environment variables for sensitive data (e.g., `SECRET_KEY`, Firebase credentials) in production.
- The `tests/` directory is not included by default; create one for unit tests if needed.

## Contact

For issues or inquiries, open a GitHub issue or contact the project maintainer.