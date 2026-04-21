require("dotenv").config()

const crypto = require("crypto")
const cors = require("cors")
const express = require("express")
const https = require("https")

const app = express()

const port = Number(process.env.PORT || 4000)
const clientId = process.env.SPOTIFY_CLIENT_ID
const clientSecret = process.env.SPOTIFY_CLIENT_SECRET
const redirectUri =
  process.env.SPOTIFY_REDIRECT_URI || `http://localhost:4000/auth/callback`
const frontendUrl = process.env.FRONTEND_URL || "http://localhost:3000"
const frontendAuthCallbackPath =
  process.env.FRONTEND_AUTH_CALLBACK_PATH || "/auth/callback"
const defaultScopes = [
  "user-read-email",
  "user-read-private",
  "user-top-read",
  "user-read-recently-played",
  "playlist-read-private",
  "playlist-read-collaborative",
  "user-library-read",
  "user-library-modify",
  "user-follow-read",
  "user-follow-modify",
]
const scope = process.env.SPOTIFY_SCOPES || defaultScopes.join(" ")
const stateCookieName = "spotify_auth_state"
const returnToCookieName = "sonara_auth_return_to"

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
  const returnTo = getValidatedReturnToUrl(req.query.return_to)

  res.cookie(stateCookieName, state, buildTransientCookieOptions())
  res.cookie(returnToCookieName, returnTo.toString(), buildTransientCookieOptions())
  const authorizeUrl = buildAuthorizeUrl(requestedScope, state)

  return res.redirect(authorizeUrl.toString())
})

app.get("/auth/callback", async (req, res) => {
  const code = req.query.code
  const returnedState = req.query.state
  const storedState = readCookie(req.headers.cookie, stateCookieName)
  const returnTo = getValidatedReturnToUrl(
    readCookie(req.headers.cookie, returnToCookieName),
  )

  if (!code || typeof code !== "string") {
    return redirectToFrontendOrRespond(res, returnTo, 400, {
      error: "code_missing",
      message: "Spotify did not return an authorization code.",
    })
  }

  if (!returnedState || typeof returnedState !== "string") {
    return redirectToFrontendOrRespond(res, returnTo, 400, {
      error: "state_missing",
      message: "Spotify did not return a state parameter.",
    })
  }

  if (!storedState || storedState !== returnedState) {
    return redirectToFrontendOrRespond(res, returnTo, 400, {
      error: "state_mismatch",
      message: "State validation failed. Start the login flow again.",
    })
  }

  if (!clientId || !clientSecret) {
    return redirectToFrontendOrRespond(res, returnTo, 500, {
      error: "spotify_credentials_missing",
      message:
        "Set SPOTIFY_CLIENT_ID and SPOTIFY_CLIENT_SECRET in Sonara-backend/.env",
    })
  }

  try {
    const { tokenResponse, tokenData } = await exchangeAuthorizationCode(code)

    if (!tokenResponse.ok) {
      return redirectToFrontendOrRespond(res, returnTo, tokenResponse.status, {
        error: "token_exchange_failed",
        details: tokenData,
      })
    }

    return redirectToFrontendOrRespond(res, returnTo, 200, {
      access_token: tokenData.access_token,
      refresh_token: tokenData.refresh_token,
      expires_in: tokenData.expires_in,
      scope: tokenData.scope,
      token_type: tokenData.token_type,
    })
  } catch (error) {
    return redirectToFrontendOrRespond(res, returnTo, 500, {
      error: "spotify_request_failed",
      message: error instanceof Error ? error.message : "Unknown error",
    })
  }
})

app.post("/auth/refresh", async (req, res) => {
  const refreshToken =
    typeof req.body?.refresh_token === "string" ? req.body.refresh_token : null

  if (!refreshToken) {
    return res.status(400).json({
      error: "refresh_token_missing",
      message: "Send a Spotify refresh token in the request body.",
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
    const { tokenResponse, tokenData } = await refreshAccessToken(refreshToken)

    if (!tokenResponse.ok) {
      return res.status(tokenResponse.status).json({
        error: "token_refresh_failed",
        details: tokenData,
      })
    }

    return res.json({
      access_token: tokenData.access_token,
      expires_in: tokenData.expires_in,
      scope: tokenData.scope,
      token_type: tokenData.token_type,
      refresh_token: tokenData.refresh_token || refreshToken,
    })
  } catch (error) {
    return res.status(500).json({
      error: "spotify_request_failed",
      message: error instanceof Error ? error.message : "Unknown error",
    })
  }
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

function buildTransientCookieOptions() {
  return {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 5 * 60 * 1000,
  }
}

function clearAuthCookies(res) {
  res.clearCookie(stateCookieName)
  res.clearCookie(returnToCookieName)
}

function buildAuthorizeUrl(requestedScope, state) {
  const authorizeUrl = new URL("https://accounts.spotify.com/authorize")
  authorizeUrl.search = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: requestedScope,
    state,
  }).toString()

  return authorizeUrl
}

function getValidatedReturnToUrl(candidate) {
  const fallbackUrl = new URL(frontendAuthCallbackPath, frontendUrl)

  if (!candidate || typeof candidate !== "string") {
    return fallbackUrl
  }

  try {
    const parsedUrl = new URL(candidate)

    if (parsedUrl.origin !== fallbackUrl.origin) {
      return fallbackUrl
    }

    return parsedUrl
  } catch {
    return fallbackUrl
  }
}

function redirectToFrontendOrRespond(res, returnTo, statusCode, payload) {
  clearAuthCookies(res)

  if (!returnTo) {
    return res.status(statusCode).json(payload)
  }

  const redirectUrl = new URL(returnTo.toString())
  redirectUrl.hash = new URLSearchParams(
    Object.entries(payload).flatMap(([key, value]) => {
      if (value === undefined || value === null) {
        return []
      }

      if (typeof value === "object") {
        return [[key, JSON.stringify(value)]]
      }

      return [[key, String(value)]]
    }),
  ).toString()

  return res.redirect(redirectUrl.toString())
}

async function exchangeAuthorizationCode(code) {
  const tokenResponse = await postSpotifyTokenRequest({
    code,
    redirect_uri: redirectUri,
    grant_type: "authorization_code",
  })
  const tokenData = await readSpotifyResponse(tokenResponse)

  return { tokenResponse, tokenData }
}

async function refreshAccessToken(refreshToken) {
  const tokenResponse = await postSpotifyTokenRequest({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
  })
  const tokenData = await readSpotifyResponse(tokenResponse)

  return { tokenResponse, tokenData }
}

function postSpotifyTokenRequest(params) {
  return new Promise((resolve, reject) => {
    const body = new URLSearchParams(params).toString()
    const authHeader = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`
    const request = https.request(
      "https://accounts.spotify.com/api/token",
      {
        method: "POST",
        headers: {
          Authorization: authHeader,
          "Content-Type": "application/x-www-form-urlencoded",
          "Content-Length": Buffer.byteLength(body),
        },
      },
      (response) => {
        const chunks = []

        response.on("data", (chunk) => {
          chunks.push(chunk)
        })

        response.on("end", () => {
          const rawBody = Buffer.concat(chunks).toString("utf8")

          resolve({
            ok: response.statusCode >= 200 && response.statusCode < 300,
            status: response.statusCode || 500,
            headers: response.headers,
            body: rawBody,
          })
        })
      },
    )

    request.on("error", reject)
    request.write(body)
    request.end()
  })
}

async function readSpotifyResponse(response) {
  const contentType = response.headers["content-type"] || ""

  if (contentType.includes("application/json")) {
    return JSON.parse(response.body)
  }

  return {
    error: "unexpected_spotify_response",
    raw: response.body,
  }
}
