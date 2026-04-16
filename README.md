# Sonara Backend

Express backend for Spotify Authorization Code Flow.

## Endpoints

- `GET /health`
- `GET /auth/login`
- `GET /auth/callback`
- `POST /auth/refresh`

## Setup

1. Copy `.env.example` to `.env`.
2. Create a Spotify app in the developer dashboard.
3. Add `http://127.0.0.1:4000/auth/callback` to the app redirect URIs.
4. Fill in `SPOTIFY_CLIENT_ID` and `SPOTIFY_CLIENT_SECRET`.
5. Install dependencies with `npm install`.
6. Start the server with `npm run dev`.

## Login Flow

Open `http://localhost:4000/auth/login`.

The backend redirects to Spotify's `/authorize` endpoint with:

- `response_type=code`
- `client_id`
- `redirect_uri`
- `scope`
- `state`

Spotify redirects back to `/auth/callback`, where the backend validates `state` and exchanges the code for tokens using `POST https://accounts.spotify.com/api/token`.

## Testing

Spotify's `/authorize` endpoint is interactive, so use a browser for the login flow:

1. Open `http://localhost:4000/auth/login` in the browser.
2. Sign in to Spotify.
3. Spotify redirects back to your backend callback and then back to your frontend callback URL with tokens in the hash.

To refresh an access token:

1. Send `POST /auth/refresh` with JSON body `{ "refresh_token": "..." }`.
