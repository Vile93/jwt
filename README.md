# JWT Auth API

Простой API на Node.js, Express 5 и SQLite. Работа с базой вынесена в класс
[`Db`](./db.js).

## Запуск

Требуется Node.js 22.5+.

```bash
npm install
npm start
```

`.env`:

```env
PORT=3000
JWT_SECRET=your-long-secret
DATABASE_FILE=./auth.sqlite
```

## Эндпоинты

| Метод  | URL                     | Назначение         |
| ------ | ----------------------- | ------------------ |
| `POST` | `/auth/register`        | Регистрация        |
| `POST` | `/auth/login`           | Вход               |
| `POST` | `/auth/refresh`         | Обновление токенов |
| `POST` | `/auth/logout`          | Выход              |
| `POST` | `/auth/change-password` | Смена пароля       |
| `GET`  | `/me`                   | Защищённый профиль |

После входа сервер устанавливает два `httpOnly` cookie:

- `access_token` — JWT access-токен на 15 минут;
- `refresh_token` — refresh-токен на 7 дней.

Браузер автоматически отправляет cookies. В JavaScript они недоступны.
Для запросов из Insomnia включи сохранение cookies в cookie jar.

## Примеры

### Регистрация

```http
POST /auth/register
Content-Type: application/json
```

```json
{
    "name": "alice",
    "password": "password123"
}
```

### Вход

```http
POST /auth/login
Content-Type: application/json
```

```json
{
    "name": "alice",
    "password": "password123"
}
```

Токены будут установлены в cookies ответа.

### Обновление токенов

```http
POST /auth/refresh
```

Refresh-токен берётся из cookie автоматически.

### Профиль

```http
GET /me
```

Access-токен берётся из cookie автоматически.

### Смена пароля

```http
POST /auth/change-password
Content-Type: application/json
```

```json
{
    "currentPassword": "password123",
    "newPassword": "new-password123"
}
```

После смены пароля все refresh-токены пользователя деактивируются, а cookies
очищаются.

## Тестирование

Проект использует встроенный раннер `node:test`.

```bash
npm run test:unit
npm run test:integration
npm test
```

- Юнит-тесты проверяют работу SQLite-хранилища, уникальность пользователей,
  обновление пароля и lifecycle refresh-токенов.
- Интеграционные тесты запускают Express-приложение на временном порту и
  проверяют регистрацию, вход, `/me`, refresh-ротацию, logout и смену пароля.

Для изоляции интеграционные тесты используют временный SQLite-файл.

## Правила

- Access-токен — JWT `HS256` на 15 минут.
- Refresh-токен хранится в базе только в виде SHA-256 хеша.
- У каждого входа может быть отдельная refresh-сессия.
- После refresh старый refresh-токен недействителен.
- При выходе текущая refresh-сессия деактивируется.
- Пароли хранятся как bcrypt-хеши.
- Истёкший access-токен возвращает `401 TOKEN_EXPIRED`.

## Insomnia

Готовая коллекция находится в
[insomnia-collection.json](./insomnia-collection.json). Импортируй её через
**Import/Export → Import Data → From File**. В коллекции включено сохранение
cookies, поэтому вручную копировать токены не нужно.
