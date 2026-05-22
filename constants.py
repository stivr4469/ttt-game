# sandbox-auditor/constants.py

# Опасные порты (используются в scanner.py)
DANGEROUS_PORTS = {
    22:   {"service": "SSH",        "severity": "CRITICAL"},
    3389: {"service": "RDP",        "severity": "CRITICAL"},
    5432: {"service": "PostgreSQL", "severity": "HIGH"},
    3306: {"service": "MySQL",      "severity": "HIGH"},
    1433: {"service": "MSSQL",      "severity": "HIGH"},
    27017:{"service": "MongoDB",    "severity": "HIGH"},
    6379: {"service": "Redis",      "severity": "HIGH"},
    9200: {"service": "Elasticsearch", "severity": "HIGH"},
}

# Уровни severity
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_LOW      = "LOW"
SEVERITY_UNKNOWN  = "UNKNOWN"

# Допустимые источники evidence
EVIDENCE_SOURCES = frozenset({
    "AWS_CLI", "OKTA", "GITHUB", "MANUAL",
    "AI_GENERATED", "SURVEY", "HR_AUDIT", "PROWLER",
    "GCP", "AZURE", "GITLAB", "AZURE_AD", "GOOGLE_WORKSPACE", "SNOWFLAKE"
})

# Пути к файлам
CONTROLS_MAP_FILE  = "controls_map.json"
HR_ROSTER_FILE     = "hr_roster.json"
MDM_INVENTORY_FILE = "mdm_device_inventory.json"
REMEDIATIONS_FILE  = "remediations.json"

# SOC 2 контроли, которые проверяются автоматически
AUTO_CONTROLS = [
    "CC6.1", "CC6.2", "CC6.3", "CC6.6", "CC6.7",
    "CC7.1", "CC7.2", "CC3.4", "CC8.1"
]

# Пороги и настройки
DORMANT_DAYS        = 90
TRAINING_GRACE_DAYS  = 30
CI_STALE_DAYS       = 30
CONTENT_MAX_BYTES   = 99_000
TITLE_MAX_CHARS     = 490
