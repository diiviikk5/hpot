# Agentic Honeypot API

AI-powered honeypot system that detects scam communications, engages scammers via intelligent AI agents, and extracts actionable fraud intelligence.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
cp .env.example .env
# Edit .env with your API keys

# Run locally
uvicorn app.main:app --reload --port 8000
```

## API Endpoints

### Health Check
```
GET /health
```

### Honeypot Endpoint
```
POST /api/honeypot
Headers: X-API-Key: your_api_key
Body: {"message": "scam text here", "conversation_id": "optional"}
```

## Deployment

Deploy to Render (free tier):
1. Connect GitHub repo
2. Set environment variables
3. Deploy

## License
MIT
