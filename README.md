# Salamador - Text Humanizer

Salamador is a web application that helps users transform AI-generated text into more human-like writing. It uses advanced NLP models to paraphrase and enhance text while preserving the original meaning.

## Features

- **Text Humanization**: Convert AI-generated text to sound more natural and human-written
- **Ultra Mode**: Enhanced humanization with advanced NLP techniques (premium feature)
- **User Authentication**: Google sign-in integration
- **History Tracking**: Save and retrieve past humanization sessions
- **Premium Subscription**: Access to advanced features and unlimited usage

## Project Structure

```
salamador/
├── app.py                  # Main Flask application
├── config.py               # Configuration settings
├── auth/
│   └── firebase_auth.py    # Firebase authentication
├── database/
│   └── db_handler.py       # Database operations
├── processor/
│   └── humanizer.py        # Text humanization logic
├── static/
│   ├── css/
│   └── js/
└── templates/
    ├── index.html          # Main application interface
    └── login.html          # Login page
```

## Installation

1. Clone the repository
2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
4. Set up Firebase:
   - Create a Firebase project
   - Enable Google authentication
   - Create a service account and download the JSON file
   - Update `config.py` with your Firebase credentials

5. Initialize the database:
   ```
   python -c "from database.db_handler import init_db; init_db()"
   ```

## Running the Application

```
python app.py
```

The application will be available at http://localhost:5000

## Development

### Adding New Features

1. Create a new branch for your feature
2. Implement the feature
3. Add tests
4. Submit a pull request

### Running Tests

```
pytest
```

## Requirements

- Python 3.8+
- Flask
- Firebase Admin SDK
- Transformers
- PyTorch
- SQLite

## Deployment

For production deployment:

1. Set proper environment variables
2. Use a production server like Gunicorn
3. Set up proper database (consider PostgreSQL)
4. Enable HTTPS with SSL certificates

## License

This project is licensed under the MIT License - see the LICENSE file for details.