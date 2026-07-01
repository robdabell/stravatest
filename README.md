# Strava API Connector

Small dependency-free Python client for connecting this workspace to your Strava account.

## 1. Create a Strava API app

Go to <https://www.strava.com/settings/api> and create an app.

Use these settings:

- **Authorization Callback Domain:** `127.0.0.1`
- The local redirect URL used by this project is `http://127.0.0.1:8787/callback`

## 2. Add local credentials

Copy `.env.example` to `.env` and fill in your Strava app credentials:

```sh
cp .env.example .env
```

Then edit `.env`.

## 3. Authorize

```sh
python3 strava.py auth
```

The command prints a Strava authorization URL. Open it, approve access, and the local callback server will save `.strava_tokens.json`.

The default scope is `read,activity:read_all`. That allows profile lookup and reading all your activities, including private activities visible only to you.

## 4. Try it

```sh
python3 strava.py athlete
python3 strava.py activities --limit 10
python3 strava.py export-activities --limit 100 --output data/activities.json
```

Tokens and exports are ignored by Git.
