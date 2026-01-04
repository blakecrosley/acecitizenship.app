# Ace Citizenship - Backend & Marketing Site

FastAPI backend and marketing website for the Ace Citizenship iOS app.

## Stack
- FastAPI (Python)
- HTMX + Alpine.js + Bootstrap 5
- Jinja2 templates
- Railway deployment

## Project Structure
```
app/
├── main.py              # FastAPI app entry
├── routes/              # API endpoints
├── templates/           # Jinja2 HTML templates
└── static/              # CSS, JS, images
```

## Commands
- `./run.sh` - Start development server
- `pip install -r requirements.txt` - Install dependencies

## Deployment
- Platform: Railway
- Config: `railway.toml`, `Procfile`

## Related
- iOS app: `~/Projects/Ace-Citizenship/`

## Key Patterns
- Server-rendered marketing pages with HTMX
- API endpoints for app backend (if any)
- Bootstrap 5 for responsive layout
