# bank-core

Spring Boot authoritative banking backend for the Banking Platform. This
repository owns the Java API, database migrations, ledger, workflows,
authentication, and backend tests. The web client, AI/KYC service, and Android
client are versioned in separate repositories.

## Related repositories

- [bank-web](https://github.com/gimesha-adikari/bank-web) — Next.js web client
- [bank-service](https://github.com/gimesha-adikari/bank-service) — FastAPI AI/KYC service
- [bank-app](https://github.com/gimesha-adikari/bank-app) — Android application

These clients and services communicate with this backend through configured HTTP
endpoints. A sibling checkout is not required for backend compilation or tests.

## Requirements

- Java 21
- MySQL 8.4 for the integration environment
- SMTP sink configuration for email-dependent tests and local flows
- Optional FastAPI service reachable through the configured `ML_BASE_URL`

## Local configuration

Copy the checked-in example configuration and provide only local sandbox values:

```bash
cp src/main/resources/application-dev.example.yml src/main/resources/application-dev.yml
```

Keep `application-dev.yml`, production configuration, credentials, and generated
runtime state out of Git. Configure the AI/KYC service URL externally (for
example with `ML_BASE_URL`); this repository does not read the AI service from a
filesystem path.

## JWT issuer and audience

`JWT_ISSUER` defaults to `bank-core` and `JWT_AUDIENCE` defaults to
`bank-core-api`. These are public logical identifiers, not secrets. Every
concurrently serving bank-core instance must use the same exact values.

AUTH-008 is a hard session cutover: newly issued JWTs require both claims, and
new Session rows store a 64-character lowercase SHA-256 fingerprint of the
exact bearer JWT in the existing `sessions.token` column. Existing raw-token
Session rows remain unchanged and cannot authorize legacy unscoped tokens.
Old and new bank-core versions must not concurrently serve authenticated
traffic; all old instances must be stopped or drained before authenticated
traffic resumes on the strict version. Users with legacy tokens must sign in
again.

## Build and test

Run from this repository root:

```bash
SPRING_CONFIG_ADDITIONAL_LOCATION="classpath:/application-dev.example.yml" \
DB_URL="jdbc:mysql://127.0.0.1:3307/banking_system_dev?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC" \
DB_USERNAME="banking_dev" \
DB_PASSWORD="change-me-locally" \
MAIL_HOST="127.0.0.1" \
MAIL_PORT="1025" \
ML_BASE_URL="http://127.0.0.1:8000" \
bash ./gradlew clean test
```

The Gradle wrapper is the authoritative build entry point. Integration tests
require the configured MySQL and local service dependencies.

## Database migrations

Flyway migrations under `src/main/resources/db/migration/` are authoritative.
Do not edit a committed migration; add a reviewed versioned migration when a
schema change is explicitly approved.

## API documentation

The backend exposes its configured OpenAPI/Swagger documentation while running.
Additional API and database notes are under `docs/`.
