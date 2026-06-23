from __future__ import annotations

import re
from typing import Dict

DEFAULT_PERM_WORDS = (
    "dev staging stage stg test qa uat beta demo preprod pre prod "
    "internal intranet vpn admin api app mail smtp ftp old new backup bak sandbox "
    "secure portal gateway cdn static assets mobile www web git gitlab jenkins ci cd "
    "jira confluence db database redis elastic kibana grafana monitor status docs "
    "support shop payments billing auth sso login"
).split()

SECRET_PATTERNS: Dict[str, str] = {
    "AWS_Access_Key_ID":   r'AKIA[0-9A-Z]{16}',
    "AWS_Secret_Key":      r'aws[\-_\s]*(secret|access)[\-_\s]*key["\']?\s*[:=]\s*["\']?[0-9a-zA-Z/+]{40}',
    "GCP_API_Key":         r'AIza[0-9A-Za-z\-_]{35}',
    "OpenAI_API_Key":      r'sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}',
    "Anthropic_API_Key":   r'sk-ant-[a-zA-Z0-9\-_]{90,}',
    "HuggingFace_Token":   r'hf_[a-zA-Z0-9]{34,}',
    "GitHub_PAT":          r'ghp_[0-9a-zA-Z]{36}',
    "GitHub_OAuth":        r'gho_[0-9a-zA-Z]{36}',
    "GitHub_Actions":      r'ghs_[0-9a-zA-Z]{36}',
    "GitLab_PAT":          r'glpat-[0-9a-zA-Z\-_]{20}',
    "npm_Token":           r'npm_[A-Za-z0-9]{36}',
    "Docker_Hub_Token":    r'dckr_pat_[A-Za-z0-9\-_]{27}',
    "Slack_Bot_Token":     r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}',
    "Slack_Webhook":       r'hooks\.slack\.com/services/T[0-9A-Za-z]+/B[0-9A-Za-z]+/[0-9A-Za-z]+',
    "Discord_Token":       r'[MN][a-zA-Z0-9]{23}\.[a-zA-Z0-9\-_]{6}\.[a-zA-Z0-9\-_]{27}',
    "Twilio_SID":          r'AC[a-zA-Z0-9]{32}',
    "SendGrid_Key":        r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}',
    "Stripe_Secret":       r'sk_(live|test)_[0-9a-zA-Z]{24,}',
    "Stripe_Pub":          r'pk_(live|test)_[0-9a-zA-Z]{24,}',
    "JWT":                 r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    "Firebase_URL":        r'https://[a-z0-9-]+\.firebaseio\.com',
    "RSA_Private_Key":     r'-----BEGIN RSA PRIVATE KEY-----',
    "EC_Private_Key":      r'-----BEGIN EC PRIVATE KEY-----',
    "OpenSSH_Private_Key": r'-----BEGIN OPENSSH PRIVATE KEY-----',
    "Bearer_Token":        r'bearer\s+[a-zA-Z0-9\-_\.=]{20,}',
    "Generic_API_Key":     r'(api[\-_]?key|apikey)["\']?\s*[:=]\s*["\']?[0-9a-zA-Z\-_]{20,}',
    "Generic_Secret":      r'(client[\-_]?secret|app[\-_]?secret)["\']?\s*[:=]\s*["\']?[0-9a-zA-Z\-_!@#$%^&*]{16,}',
    "Generic_Password":    r'(password|passwd|db[\-_]?pass)["\']?\s*[:=]\s*["\']?[^\s"\']{8,}',
    "Connection_String":   r'(mongodb(\+srv)?|mysql|postgres|redis|amqp)://[^\s"\'<>]+',
    "AWS_Session_Token":   r'aws[\-_\s]*session[\-_\s]*token["\']?\s*[:=]\s*["\']?[A-Za-z0-9/+=]{100,}',
    "Azure_Client_Secret": r'azure[\-_\s]*(client|tenant)[\-_\s]*(secret|id)["\']?\s*[:=]\s*["\']?[0-9a-zA-Z\-]{20,}',
    "Shopify_Token":       r'shp(ss|at|ca)_[a-fA-F0-9]{32}',
    "PayPal_OAuth":        r'access_token\$production\$[a-zA-Z0-9]{16}\$[a-zA-Z0-9]{32}',
    "Vercel_Token":        r'vercel(.{0,10})?token["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{24,}',
    "Notion_Token":        r'secret_[a-zA-Z0-9]{43}',
    "Linear_Key":          r'lin_api_[a-zA-Z0-9]{40}',
}
_COMBINED_RE = re.compile(
    "|".join(f"(?P<p{i}>{v})" for i, v in enumerate(SECRET_PATTERNS.values())),
    re.IGNORECASE
)

BACKUP_EXT_RE = re.compile(
    r'\.(zip|rar|7z|tar\.gz|tgz|tar|gz|bak|bkp|backup|old|orig|save|swp|'
    r'sql|sql\.gz|db|sqlite3?|config|conf|ini|env|pem|key|crt|p12|pfx|'
    r'log|csv|xls|xlsx|doc|docx|htpasswd|htaccess|git)(\?.*)?$',
    re.IGNORECASE)
URL_SECRET_RE = re.compile(
    r'(?i)(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret|token|'
    r'passwd|password|session[_-]?id|aws[_-]?(access|secret)[_-]?key)=[^&\s"\']{4,}')
