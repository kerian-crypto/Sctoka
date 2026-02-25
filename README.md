# Stocka API

## D?marrage local

1. `python -m venv .venv`
2. `.venv\Scripts\activate`
3. `pip install -r requirements.txt`
4. `flask --app app:create_app db init`
5. `flask --app app:create_app db migrate -m "init"`
6. `flask --app app:create_app db upgrade`
7. `python app.py`

## Variables d'environnement

Copier `.env.example` vers `.env` puis adapter:

- `SECRET_KEY`
- `JWT_SECRET_KEY`
- `JWT_EXPIRES_HOURS`
- `DATABASE_URL`
- `CORS_ORIGINS`
- `PORT`

## Auth JWT et roles

- Roles supportes: `admin`, `magasinier`, `comptable`
- L'API exige `Authorization: Bearer <token>` pour les routes metier.
- Connexion: `POST /auth/login` avec `{email, password}`
- Profil courant: `GET /auth/me`
- Gestion utilisateurs (admin):
  - `GET /auth/users`
  - `POST /auth/users`
  - `PUT /auth/users/<id>`
  - `DELETE /auth/users/<id>`

Compte admin seed automatique (modifiable via `.env`):
- `DEFAULT_ADMIN_EMAIL` (defaut `admin@stocka.local`)
- `DEFAULT_ADMIN_PASSWORD` (defaut `Admin123!`)

## Production (Gunicorn)

Commande:

`gunicorn -c gunicorn.conf.py wsgi:app`

Exemple avec Nginx:

- reverse proxy sur `http://127.0.0.1:5000`
- TLS obligatoire
- limiter CORS aux domaines front autoris?s
