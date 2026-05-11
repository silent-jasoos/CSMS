# CyberShield CSMS

CyberShield CSMS is a university capstone project built to simulate a modern cybersecurity management system for educational and lab environments. It combines firewall control, intrusion detection, honeypot monitoring, and security reporting into a unified platform designed for students, analysts, and instructors who want hands-on experience with defensive cyber operations.

## Features

- ?? Authentication System
- ??? Firewall Engine
- ?? Intrusion Detection System (IDS)
- ??? Honeypot
- ?? Attack Logger
- ?? Report Generator

## Tech Stack

| Layer | Technology | Version | Purpose |
|---|---|---|---|
| Backend | Java / Spring Boot | 17 | Core server, API, business logic |
| Frontend | HTML + CSS + JavaScript + Thymeleaf | N/A | User interface and interactive dashboards |
| Database | MySQL | 8.0 | Persistent storage for users, rules, alerts, and logs |
| Security | JWT + BCrypt | N/A | Authentication, authorization, password hashing |
| Charts | Chart.js | Latest | Visual reporting and dashboard charts |
| Build | Maven | 3.9+ | Project build, dependency management, packaging |

## Prerequisites

1. JDK 17 — https://adoptium.net
   - Verify: `java -version`
2. Apache Maven 3.9+ — https://maven.apache.org
   - Verify: `mvn -version`
3. MySQL 8.0 — https://dev.mysql.com/downloads/installer/
   - Verify: `mysql --version`
4. IntelliJ IDEA Community — https://www.jetbrains.com/idea/download/

## Setup Steps

1. Download or clone the project folder.
2. Open MySQL Workbench, run:
   ```sql
   CREATE DATABASE cybershield_db;
   ```
3. In MySQL Workbench open and run `schema.sql` from `src/main/resources/`.
4. Open `application.properties`, update `spring.datasource.password` if different from `CyberShield@2024`.
5. Open IntelliJ IDEA, go to `File > Open`, select the `cybershield-csms` folder, and wait for Maven to finish importing.
6. Right-click `CyberShieldApplication.java` and choose `Run`.
7. Wait for the `Started CyberShieldApplication` message in the console.
8. Open browser: `http://localhost:8080`

## Default Login Credentials

| Username | Password | Role | Access Level |
|---|---|---|---|
| `admin` | `Admin@123` | ADMIN | Full access |
| `analyst1` | `Analyst@123` | ANALYST | View only |
| `student1` | `Student@123` | VIEWER | Monitor only |

## Network Setup (For Lab Use)

1. On admin PC: run `ipconfig`, note the IPv4 address (e.g. `192.168.1.105`).
2. Windows Firewall: allow port `8080` inbound via `Control Panel > Firewall > Advanced > Inbound Rules > New`.
3. On other PCs: open browser and go to `http://192.168.1.105:8080`.

## Project Structure

- `src/main/java/` — Java backend source files.
- `src/main/resources/` — application properties, SQL scripts, templates.
- `src/main/resources/templates/` — Thymeleaf HTML pages.
- `src/main/resources/static/` — frontend assets, CSS, JavaScript.
- `pom.xml` — Maven build configuration.
- `README.md` — project documentation.

## OOP Design Patterns

| Pattern | Class | Description |
|---|---|---|
| Singleton | `AttackLogger` | Only one logger instance exists across the app |
| Observer | All modules -> `AttackLogger` | Modules notify logger automatically when events occur |
| Strategy | `IDSScanner` + `AttackPatterns` | Swap detection algorithms without changing client code |
| Factory | `ReportGenerator` | Creates different report types dynamically |
| Inheritance | `BaseEntity` -> all entities | Common fields shared via parent entity class |
| Encapsulation | `User.java` (all entities) | Private fields with getters/setters hide implementation details |
| Polymorphism | `AttackPattern` implementations | Same interface, different behaviors for detection rules |

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `Access denied for root` | Wrong DB password | Update `application.properties` |
| `Port 8080 in use` | Another app using 8080 | Add `server.port=8081` |
| `Unknown database` | `schema.sql` not run | Run `schema.sql` in Workbench first |
| `java not found` | `JAVA_HOME` not set | Set environment variable, reopen terminal |

## Team

| Person | Role | Files Owned |
|---|---|---|
| Zeeshan Akhtar | Backend Lead | Java backend, security, patterns (30 files) |
| Zayan Khan | Database Manager | `schema.sql`, repositories (5 files) |
| Agha Ahmed | Frontend Developer | HTML templates, CSS (10 files) |
| Aftab Yaseen| JS Developer | JavaScript files, README (6 files) |
