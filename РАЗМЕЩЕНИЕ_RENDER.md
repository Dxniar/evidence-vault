# Evidence Vault: бесплатное размещение на Render

Проверено по официальной документации **13 октября 2026 года**. Проект уже размещён на **Render Free Web Service** и использует существующие **Supabase PostgreSQL и Storage**.

- Сайт: [evidence-vault-dxniar.onrender.com](https://evidence-vault-dxniar.onrender.com).
- Исходники: [Dxniar/evidence-vault](https://github.com/Dxniar/evidence-vault), публичный репозиторий с согласия владельца.
- Панель сервиса: [Render Dashboard](https://dashboard.render.com/web/srv-db79peid0e5s73fq76hg).
- Первое размещение: `df07200e2f86d455d7b8cda8511e9cf96fefd521`, завершилось **14 октября 2026 года в 02:04 (Asia/Qyzylorda)**. Тариф — `free`, регион — `singapore`. Результаты последующих обновлений сохраняются локально в `output/deploy/deployment.json`.
- Проверки `/healthz`, `/readyz`, `/login`, CSS и JavaScript вернули HTTP 200; `/readyz` подтвердил подключение БД и Storage. Результаты сохранены в `output/deploy/http-verification.json`.
- Google-вход и TOTP **проверены на опубликованном сайте**: после возврата Google открылось «Подтвердите вход», пользователь ввёл код из своего аутентификатора, затем открылась страница `/dashboard` с заголовком «Обзор · Evidence Vault». Лишняя точка после `callback` в настройках Google исправлена и сохранена; повторное открытие клиента подтвердило точный адрес. Техническая проверка сохранена в `output/deploy/oauth-redirect-check.json`, подтверждение настроек — в `output/deploy/google-redirect-saved.jpg`, успешный вход — в `output/deploy/google-login-dashboard.jpg`.

Ниже приведены настройки действующего размещения и порядок дальнейших обновлений. Секреты, локальные данные и результаты проверок в публичный репозиторий не отправлены.

## 1. Проверьте Supabase

- Используйте уже настроенный проект, если хотите сохранить пользователей, дела и настройки 2FA.
- В **Connect → Session pooler** скопируйте строку PostgreSQL с портом **5432**. Render использует IPv4; прямой адрес `db.<project-ref>.supabase.co` на бесплатном Supabase рассчитан на IPv6. Имя pooler берите из панели, пароль со специальными символами URL-кодируйте. **Transaction pooler на 6543 для этого приложения не используйте.** [Совместимость сетей](https://supabase.com/docs/guides/troubleshooting/supabase--your-network-ipv4-and-ipv6-compatibility-cHe3BP), [подключение PostgreSQL](https://supabase.com/docs/guides/database/connecting-to-postgres).
- Bucket `evidence-private` должен оставаться **Private**. Лимит размера в bucket и глобальных настройках Storage — не меньше 16 МБ; ограничений MIME у bucket быть не должно. Браузеру серверный ключ не передаётся.
- Подготовьте URL проекта и серверный `SUPABASE_SECRET_KEY` из **Settings → API Keys**. Значения не вставляйте в исходники или эту инструкцию.

## 2. Подготовьте базу перед размещением

В локальной `.env` должны быть параметры **той Supabase-базы, которую будет использовать Render**. Для существующей базы сначала сохраните резервную копию. Из корня проекта выполните:

```powershell
docker compose build
docker compose run --rm web flask --app app:create_app check-setup
docker compose run --rm web flask --app app:create_app db upgrade
```

Это явный вариант команд из `README.md`, где используется автоматическое обнаружение фабрики через `--app app`. `check-setup` проверяет БД и настройки приватного bucket; `db upgrade` применяет миграции. При уже существующем администраторе **не повторяйте `bootstrap-admin`**. Для новой пустой базы порядок создания первого администратора описан в `README.md`.

Миграции выполняйте **до** ручного размещения каждой новой версии. На Render Free нет команд `preDeployCommand` и доступа к shell сервиса; поэтому отдельного запуска миграций в `render.yaml` нет. [Команды размещения](https://render.com/docs/deploys), [ограничения Free](https://render.com/docs/free).

## 3. Обновляйте исходники в Git-репозитории

Исходники уже опубликованы в [Dxniar/evidence-vault](https://github.com/Dxniar/evidence-vault), ветка `main`. В размещённую версию вошли 77 файлов проекта, включая `Dockerfile`, `render.yaml`, `requirements.txt`, миграции, шаблоны, статические файлы и код лабораторных заданий. Публикация выполнена через подключение GitHub; локальная папка при этом не была инициализирована как Git-репозиторий. Для последующих обновлений используйте этот же репозиторий.

Перед каждой отправкой проверьте список файлов: `.env`, содержимое `instance`, локальные базы, тестовые отчёты `output`, виртуальные окружения и ключи туда попадать не должны. В проекте уже есть `.gitignore` и `.dockerignore`; `.env.example` содержит только образцы настроек. При необходимости Render также поддерживает приватный репозиторий. [Создание Web Service](https://render.com/docs/web-services).

## 4. Создайте Render Web Service

Действующий сервис `evidence-vault-dxniar` уже создан в рабочем пространстве **«Данияр's workspace»**. Автоматическое размещение отключено; обновления запускаются вручную после проверки миграций. Не создавайте второй сервис для обновления проекта.

Если потребуется создать отдельный экземпляр, в Render выберите **New → Web Service**, подключите репозиторий и задайте:

| Настройка | Значение |
| --- | --- |
| Runtime / Language | Docker |
| Dockerfile | `./Dockerfile` |
| Compute plan | **Free** |
| Health Check Path | `/healthz` |
| Auto-Deploy | **Off** |
| Регион | По возможности рядом с регионом Supabase |

При создании действующего сервиса через подключение Render отдельный `Health Check Path` не был задан: используется стандартная проверка доступности порта. Маршруты `/healthz` и `/readyz` проверены отдельно по публичному HTTPS-адресу.

Либо используйте **New → Blueprint** и файл `render.yaml`: он описывает один бесплатный Docker-сервис, проверку `/healthz` и ручные обновления. В нём нет новых БД, дисков или платных ресурсов. Поле `autoDeployTrigger: off` — актуальный эквивалент устаревшего `autoDeploy: false`. [Формат Blueprint](https://render.com/docs/blueprint-spec).

Render предоставляет приложению `PORT` (по умолчанию `10000`). Docker-запуск проекта должен использовать этот порт и адрес `0.0.0.0`; проброс порта из локального `compose.yaml` на Render не применяется. [Порты и HTTPS](https://render.com/docs/web-services).

## 5. Заполните Environment

На действующем сервисе параметры Supabase и Google уже настроены, а для сеансов создан отдельный облачный секрет. Секреты храните только в Environment Render. При создании Blueprint переменные с `sync: false` запрашиваются отдельно; при последующих обновлениях новые переменные добавляйте через **Environment**. [Передача секретов](https://render.com/docs/blueprint-spec).

| Переменная | Что указать |
| --- | --- |
| `EVIDENCE_VAULT_SECRET` | Отдельный случайный секрет не короче 32 символов; не значение из `.env.example` |
| `DATABASE_URL` | Строка Supabase Session pooler, порт 5432 |
| `SUPABASE_URL` | URL существующего проекта Supabase |
| `SUPABASE_SECRET_KEY` | Серверный secret key Supabase |
| `SUPABASE_STORAGE_BUCKET` | Имя существующего приватного bucket, обычно `evidence-private` |
| `APP_ALLOWED_HOSTS` | Необязательно для стандартного Render-адреса: Docker автоматически принимает `RENDER_EXTERNAL_HOSTNAME`. Для собственного домена перечислите его и Render-домен, **без** `https://` и пути |
| `TRUST_PROXY_COUNT` | `1` — для запуска за доверенным HTTPS-прокси Render |
| `GOOGLE_OAUTH_CLIENT_ID` | ID настроенного веб-клиента Google, если нужен Google-вход |
| `GOOGLE_OAUTH_CLIENT_SECRET` | Секрет того же Google-клиента |

Для нового секрета можно локально выполнить `python -c "import secrets; print(secrets.token_urlsafe(48))"`. Сохраняйте секрет стабильным между обновлениями; его смена завершает прежние сеансы.

Для стандартного адреса Docker использует назначенный Render `RENDER_EXTERNAL_HOSTNAME`, если `APP_ALLOWED_HOSTS` не задан. Явно заданный список имеет приоритет. При добавлении собственного домена включите его и Render-домен в список через запятую: Render использует собственный домен в заголовке Host проверки состояния, если он подтверждён. [Проверки состояния](https://render.com/docs/health-checks).

Для отключённого Google-входа не задавайте обе Google-переменные; если используете Blueprint, удалите два соответствующих пункта из `render.yaml` до его создания. Одна заполненная Google-переменная намеренно блокирует запуск приложения.

## 6. Обновите Google OAuth

При каждом новом входе и привязке Google приложение передаёт `prompt=select_account`, чтобы Google показывал выбор аккаунта, даже если браузер уже авторизован. Следователь входит после Google без отдельного локального TOTP. Администратор и аудитор, а также все пользователи при входе по почте и паролю подтверждают TOTP Evidence Vault. Для повторной демонстрации выйдите из Evidence Vault и снова нажмите «Войти через Google».

В **Google Auth Platform → Clients → ваш Web application → Authorized redirect URIs** добавьте **точный** адрес:

```text
https://evidence-vault-dxniar.onrender.com/auth/google/callback
```

В конце адреса **нет точки и слеша**. Ранее в записи Google была обнаружена лишняя точка после `callback`; она исправлена, сохранение и точный адрес подтверждены повторным открытием клиента. Новая попытка Google-входа и TOTP завершилась открытием «Обзора». Локальный `http://localhost:8080/auth/google/callback` можно сохранить отдельной записью. Для собственного домена добавьте отдельный HTTPS callback. Схема, имя хоста и весь путь должны совпадать с адресом приложения; иначе Google вернёт `redirect_uri_mismatch`. В режиме Testing добавьте используемые Google-аккаунты в тестовые пользователи. [Настройка Google OAuth](https://developers.google.com/identity/protocols/oauth2/web-server).

## 7. Разместите и проверьте

Нажмите **Manual Deploy → Deploy latest commit**. После успешной сборки откройте HTTPS-адрес сервиса и проверьте:

1. `/healthz` возвращает `{"status":"ok"}`. Это проверка процесса; доступность БД и Storage она не подтверждает.
2. Вход существующим пользователем, Google-вход и TOTP.
3. Создание тестового дела, загрузку, скачивание и SHA-256 тестового файла.
4. Светлую/тёмную темы и мобильное меню.
5. Роли: аудитор не загружает файлы; следователь видит свои дела; администратор управляет пользователями.

Настройки подключения и команды переноса БД не должны появляться в публичном интерфейсе. При ошибке запуска смотрите Logs Render; если `/healthz` возвращает 400, сначала проверьте `APP_ALLOWED_HOSTS`.

## Бесплатные ограничения

Render Free засыпает после **15 минут** без входящих запросов; следующий запуск занимает около **минуты**. Доступно **750 часов в месяц на рабочее пространство**. Файловая система временная; постоянный диск и shell недоступны. При необычно большом исходящем трафике к внешним БД/API/Storage сервис могут приостановить. Превышение включённых лимитов сборки и трафика может привести к приостановке без способа оплаты либо к начислениям при добавленной карте. Для учебной демонстрации это приемлемо; гарантии постоянной доступности бесплатный тариф не даёт. [Render Free](https://render.com/docs/free).

Supabase Free включает **500 МБ БД и 1 ГБ файлов**, 5 ГБ исходящего и 5 ГБ кешированного трафика. При низкой активности за неделю проект может приостановиться — перед защитой проверьте его состояние в Dashboard. [Тариф Supabase](https://supabase.com/pricing), [пауза проектов](https://supabase.com/docs/guides/platform/free-project-pausing).

Для текущей архитектуры PythonAnywhere Free не подходит: внешняя PostgreSQL-база недоступна. [Ответ PythonAnywhere](https://www.pythonanywhere.com/forums/topic/35889/). Koyeb имеет бесплатный сервис, но требует карту; текущий FAQ также описывает первоначальное списание за выбранный при регистрации Pro. [Koyeb: оплата](https://www.koyeb.com/docs/faqs/pricing).
