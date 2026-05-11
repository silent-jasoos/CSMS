-- =============================================================
--  CyberShield CSMS — Database Schema
--  Database: cybershield_db
--  MySQL 8.0
--  Person B deliverable: schema.sql
-- =============================================================

USE cybershield_db;

-- =============================================================
-- TABLE: users
-- Stores login credentials, roles, account-lock status,
-- and last-login tracking for every system user.
-- =============================================================
CREATE TABLE IF NOT EXISTS users (
    id                    BIGINT        NOT NULL AUTO_INCREMENT,
    username              VARCHAR(50)   NOT NULL,
    password              VARCHAR(255)  NOT NULL,
    email                 VARCHAR(100),
    role                  ENUM('ADMIN','ANALYST','VIEWER') DEFAULT 'VIEWER',
    is_active             BOOLEAN       DEFAULT TRUE,
    failed_login_attempts INT           DEFAULT 0,
    locked_until          DATETIME,
    last_login_at         DATETIME,
    last_login_ip         VARCHAR(45),
    created_at            DATETIME      DEFAULT CURRENT_TIMESTAMP,
    updated_at            DATETIME      DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_username (username),
    UNIQUE KEY uk_email    (email)
);

-- =============================================================
-- TABLE: firewall_rules
-- Stores all firewall rules that the firewall engine checks.
-- Rules contain IP address, port, protocol, and
-- ALLOW/BLOCK action, evaluated in ascending priority order.
-- =============================================================
CREATE TABLE IF NOT EXISTS firewall_rules (
    id          BIGINT        NOT NULL AUTO_INCREMENT,
    rule_name   VARCHAR(100)  NOT NULL,
    ip_address  VARCHAR(50)   NOT NULL,
    port_number INT,
    protocol    ENUM('TCP','UDP','BOTH') DEFAULT 'TCP',
    action      ENUM('ALLOW','BLOCK')   NOT NULL,
    priority    INT           DEFAULT 50,
    is_active   BOOLEAN       DEFAULT TRUE,
    created_by  VARCHAR(50),
    created_at  DATETIME      DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME      DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_priority  (priority),
    INDEX idx_is_active (is_active)
);

-- =============================================================
-- TABLE: log_entries
-- Records every single event in the system: logins,
-- firewall blocks, IDS alerts, honeypot captures, etc.
-- High-volume table — indexed on common filter columns.
-- =============================================================
CREATE TABLE IF NOT EXISTS log_entries (
    id            BIGINT        NOT NULL AUTO_INCREMENT,
    timestamp     DATETIME      DEFAULT CURRENT_TIMESTAMP,
    event_type    VARCHAR(50),
    source_ip     VARCHAR(45),
    target_module VARCHAR(50),
    severity      ENUM('LOW','MEDIUM','HIGH','CRITICAL'),
    username      VARCHAR(50),
    description   TEXT,
    machine_name  VARCHAR(100),
    created_at    DATETIME      DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME      DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_event_type (event_type),
    INDEX idx_source_ip  (source_ip),
    INDEX idx_timestamp  (timestamp)
);

-- =============================================================
-- TABLE: ids_alerts
-- Stores Intrusion Detection System detections with
-- severity levels. Alerts can be marked resolved by analysts.
-- =============================================================
CREATE TABLE IF NOT EXISTS ids_alerts (
    id          BIGINT      NOT NULL AUTO_INCREMENT,
    alert_type  VARCHAR(50),
    source_ip   VARCHAR(45),
    target_port INT,
    severity    ENUM('LOW','MEDIUM','HIGH','CRITICAL'),
    description TEXT,
    detected_at DATETIME    DEFAULT CURRENT_TIMESTAMP,
    is_resolved BOOLEAN     DEFAULT FALSE,
    created_at  DATETIME    DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME    DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_is_resolved (is_resolved),
    INDEX idx_severity    (severity)
);

-- =============================================================
-- TABLE: honeypot_captures
-- Records attacker credentials captured by the fake login
-- trap (honeypot): IP, username, password, browser info,
-- and session duration.
-- =============================================================
CREATE TABLE IF NOT EXISTS honeypot_captures (
    id                       BIGINT       NOT NULL AUTO_INCREMENT,
    captured_ip              VARCHAR(45),
    captured_username        VARCHAR(100),
    captured_password        VARCHAR(255),
    browser_info             TEXT,
    timestamp                DATETIME     DEFAULT CURRENT_TIMESTAMP,
    session_duration_seconds BIGINT,
    created_at               DATETIME     DEFAULT CURRENT_TIMESTAMP,
    updated_at               DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);


-- =============================================================
--  SAMPLE / SEED DATA
-- =============================================================

-- ---------------------------------------------------------------
-- USERS
-- Passwords are BCrypt hashes (Spring Security compatible).
--   admin    -> Admin@123
--   analyst1 -> Analyst@123
--   student* -> Student@123
-- ---------------------------------------------------------------
INSERT INTO users (username, password, email, role, is_active, failed_login_attempts)
VALUES
(
    'admin',
    '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LnaeB8.TWap',
    'admin@cybershield.local',
    'ADMIN',
    TRUE,
    0
),
(
    'analyst1',
    '$2a$10$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW',
    'analyst1@cybershield.local',
    'ANALYST',
    TRUE,
    0
),
(
    'student1',
    '$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO1icxwkPqK',
    'student1@cybershield.local',
    'VIEWER',
    TRUE,
    0
),
(
    'student2',
    '$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO1icxwkPqK',
    'student2@cybershield.local',
    'VIEWER',
    TRUE,
    0
),
(
    'student3',
    '$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO1icxwkPqK',
    'student3@cybershield.local',
    'VIEWER',
    TRUE,
    0
);

-- ---------------------------------------------------------------
-- FIREWALL RULES  (ordered by ascending priority in sample data)
-- ---------------------------------------------------------------
INSERT INTO firewall_rules (rule_name, ip_address, port_number, protocol, action, priority, is_active, created_by)
VALUES
('Block Known Attacker', '10.0.0.99',   0,    'BOTH', 'BLOCK', 1,  TRUE, 'admin'),
('Allow Internal LAN',  '192.168.*',    0,    'BOTH', 'ALLOW', 5,  TRUE, 'admin'),
('Block SSH',           '0.0.0.0',      22,   'TCP',  'BLOCK', 10, TRUE, 'admin'),
('Block RDP',           '0.0.0.0',      3389, 'TCP',  'BLOCK', 20, TRUE, 'admin'),
('Block Telnet',        '0.0.0.0',      23,   'TCP',  'BLOCK', 30, TRUE, 'admin'),
('Allow HTTP',          '0.0.0.0',      80,   'TCP',  'ALLOW', 50, TRUE, 'admin');

-- ---------------------------------------------------------------
-- LOG ENTRIES  (12 diverse events spread over last 24 hours)
-- ---------------------------------------------------------------
INSERT INTO log_entries (event_type, source_ip, target_module, severity, username, description, machine_name, timestamp)
VALUES
('LOGIN_SUCCESS',    '192.168.1.10', 'AUTH',      'LOW',      'admin',    'Admin logged in successfully.',                          'WORKSTATION-01', NOW() - INTERVAL 23 HOUR),
('LOGIN_FAIL',       '10.0.0.55',   'AUTH',      'MEDIUM',   'unknown',  'Failed login attempt — bad password.',                   'UNKNOWN',        NOW() - INTERVAL 22 HOUR),
('FIREWALL_BLOCK',   '10.0.0.99',   'FIREWALL',  'HIGH',     NULL,       'Blocked known attacker IP on port 443.',                 'FW-GATEWAY',     NOW() - INTERVAL 20 HOUR),
('IDS_ALERT',        '10.0.0.75',   'IDS',       'CRITICAL', NULL,       'SQL injection attempt detected on /api/login.',          'IDS-SENSOR-01',  NOW() - INTERVAL 18 HOUR),
('HONEYPOT_CAPTURE', '10.0.0.88',   'HONEYPOT',  'HIGH',     NULL,       'Attacker entered fake credentials in honeypot trap.',    'HONEYPOT-SRV',   NOW() - INTERVAL 16 HOUR),
('LOGIN_FAIL',       '192.168.1.50','AUTH',       'MEDIUM',   'student1', 'Consecutive failed logins (attempt 3/5).',               'LAPTOP-12',      NOW() - INTERVAL 14 HOUR),
('ACCOUNT_LOCKED',   '192.168.1.50','AUTH',       'HIGH',     'student1', 'Account locked after 5 failed attempts.',               'LAPTOP-12',      NOW() - INTERVAL 13 HOUR),
('FIREWALL_BLOCK',   '10.0.0.33',   'FIREWALL',  'MEDIUM',   NULL,       'Blocked SSH connection attempt on port 22.',             'FW-GATEWAY',     NOW() - INTERVAL 10 HOUR),
('IDS_ALERT',        '10.0.0.20',   'IDS',       'HIGH',     NULL,       'Port scan detected from external host.',                 'IDS-SENSOR-02',  NOW() - INTERVAL 8  HOUR),
('LOGIN_SUCCESS',    '192.168.1.20','AUTH',       'LOW',      'analyst1', 'Analyst1 logged in for shift review.',                  'ANALYST-PC',     NOW() - INTERVAL 6  HOUR),
('FIREWALL_BLOCK',   '10.0.0.44',   'FIREWALL',  'CRITICAL', NULL,       'DDoS traffic detected — blocking source IP.',           'FW-GATEWAY',     NOW() - INTERVAL 3  HOUR),
('LOGIN_FAIL',       '10.0.0.12',   'AUTH',       'MEDIUM',   'unknown',  'Brute-force attempt — unknown username tried.',          'UNKNOWN',        NOW() - INTERVAL 1  HOUR);

-- ---------------------------------------------------------------
-- IDS ALERTS  (4 alerts, mixed severity and resolved status)
-- ---------------------------------------------------------------
INSERT INTO ids_alerts (alert_type, source_ip, target_port, severity, description, is_resolved, detected_at)
VALUES
('BRUTE_FORCE',   '10.0.0.55',  22,   'HIGH',     'SSH brute-force attack detected — 50+ attempts in 60 seconds.',     FALSE, NOW() - INTERVAL 22 HOUR),
('PORT_SCAN',     '10.0.0.20',  0,    'MEDIUM',   'Full TCP port scan across subnet 10.0.0.0/24.',                      TRUE,  NOW() - INTERVAL 8  HOUR),
('SQL_INJECTION', '10.0.0.75',  8080, 'CRITICAL', 'SQL injection payload found in POST /api/login request body.',       FALSE, NOW() - INTERVAL 18 HOUR),
('DDOS_ATTACK',   '10.0.0.44',  80,   'CRITICAL', 'HTTP flood DDoS — 10,000+ requests/sec to port 80 detected.',       FALSE, NOW() - INTERVAL 3  HOUR);

-- ---------------------------------------------------------------
-- HONEYPOT CAPTURES  (3 fake attacker entries)
-- ---------------------------------------------------------------
INSERT INTO honeypot_captures (captured_ip, captured_username, captured_password, browser_info, session_duration_seconds, timestamp)
VALUES
(
    '10.0.0.88',
    'administrator',
    'P@ssw0rd123',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
    47,
    NOW() - INTERVAL 16 HOUR
),
(
    '10.0.0.91',
    'root',
    'toor',
    'curl/7.88.1',
    8,
    NOW() - INTERVAL 10 HOUR
),
(
    '10.0.0.103',
    'superuser',
    'admin1234!',
    'python-requests/2.31.0',
    23,
    NOW() - INTERVAL 4 HOUR
);