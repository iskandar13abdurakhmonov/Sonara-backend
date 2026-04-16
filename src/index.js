require("dotenv").config()

const crypto = require("crypto")
const cors = require("cors")
const express = require("express")

const app = express()

const port = Number(process.env.PORT || 4000)
const clientId = process.env.SPOTIFY_CLIENT_ID
const clientSecret = process.env.SPOTIFY_CLIENT_SECRET
const redirectUri =
  process.env.SPOTIFY_REDIRECT_URI || `http://localhost:${port}/auth/callback`
const frontendUrl = process.env.FRONTEND_URL || "http://localhost:3000"
const defaultScopes = [
  "user-read-email",
  "user-read-private",
  "user-top-read",
  "user-read-recently-played",
  "playlist-read-private",
  "playlist-read-collaborative",
]
const scope = process.env.SPOTIFY_SCOPES || defaultScopes.join(" ")
const stateCookieName = "spotify_auth_state"

app.use(
  cors({
    origin: frontendUrl,
    credentials: true,
  }),
)
app.use(express.json())

app.get("/health", (_req, res) => {
  res.json({ ok: true })
})

app.get("/auth/login", (req, res) => {
  if (!clientId) {
    return res.status(500).json({
      error: "spotify_client_id_missing",
      message: "Set SPOTIFY_CLIENT_ID in Sonara-backend/.env",
    })
  }

  const state = crypto.randomBytes(16).toString("hex")
  const requestedScope =
    typeof req.query.scope === "string" && req.query.scope.trim()
      ? req.query.scope.trim()
      : scope

  res.cookie(stateCookieName, state, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 5 * 60 * 1000,
  })

  const authorizeUrl = new URL("https://accounts.spotify.com/authorize")
  authorizeUrl.search = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: requestedScope,
    state,
  }).toString()

  return res.redirect(authorizeUrl.toString())
})

app.get("/auth/callback", async (req, res) => {
  const code = req.query.code
  const returnedState = req.query.state
  const storedState = readCookie(req.headers.cookie, stateCookieName)

  if (!code || typeof code !== "string") {
    return res.status(400).json({
      error: "code_missing",
      message: "Spotify did not return an authorization code.",
    })
  }

  if (!returnedState || typeof returnedState !== "string") {
    return res.status(400).json({
      error: "state_missing",
      message: "Spotify did not return a state parameter.",
    })
  }

  if (!storedState || storedState !== returnedState) {
    return res.status(400).json({
      error: "state_mismatch",
      message: "State validation failed. Start the login flow again.",
    })
  }

  if (!clientId || !clientSecret) {
    return res.status(500).json({
      error: "spotify_credentials_missing",
      message:
        "Set SPOTIFY_CLIENT_ID and SPOTIFY_CLIENT_SECRET in Sonara-backend/.env",
    })
  }

  try {
    const tokenResponse = await fetch("https://accounts.spotify.com/api/token", {
      method: "POST",
      headers: {
        Authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        code,
        redirect_uri: redirectUri,
        grant_type: "authorization_code",
      }),
    })

    const tokenData = await tokenResponse.json()

    if (!tokenResponse.ok) {
      return res.status(tokenResponse.status).json({
        error: "token_exchange_failed",
        details: tokenData,
      })
    }

    res.clearCookie(stateCookieName)

    return res.json({
      access_token: tokenData.access_token,
      refresh_token: tokenData.refresh_token,
      expires_in: tokenData.expires_in,
      scope: tokenData.scope,
      token_type: tokenData.token_type,
    })
  } catch (error) {
    return res.status(500).json({
      error: "spotify_request_failed",
      message: error instanceof Error ? error.message : "Unknown error",
    })
  }
})

app.get("/auth/config", (_req, res) => {
  res.json({
    redirectUri,
    frontendUrl,
    scope,
  })
})

app.listen(port, () => {
  console.log(`Sonara backend listening on http://localhost:${port}`)
})

function readCookie(cookieHeader = "", key) {
  if (!cookieHeader) {
    return null
  }

  const cookies = cookieHeader.split(";")

  for (const cookie of cookies) {
    const [rawName, ...rawValue] = cookie.trim().split("=")

    if (rawName === key) {
      return decodeURIComponent(rawValue.join("="))
    }
  }

  return null
}
