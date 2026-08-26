# MarketHub Backend

Express + SQLite demo backend.

## Render
Create a new Web Service from the `backend` folder.
Build: `npm install`
Start: `npm start`

Set environment variables:
- `JWT_SECRET` = a long random value
- `ADMIN_USER` = your admin username
- `ADMIN_PASS` = your admin password

The default DB is SQLite (`markethub.db`). For production, use a persistent disk or replace SQLite with a managed PostgreSQL database.

## API
- POST `/api/auth/register`
- POST `/api/auth/login`
- GET `/api/me`
- GET/POST `/api/listings`
- GET `/api/my/listings`
- POST `/api/orders`
- GET `/api/my/orders`
- POST/GET `/api/services`
- Admin routes under `/api/admin/*`
