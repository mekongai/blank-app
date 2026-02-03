"""
Handler Outbound Checker - Kiểm tra Handler có thực hiện outbound calls

Module này phân tích code Python để phát hiện các loại outbound calls:
1. HTTP/HTTPS requests (requests, urllib, httpx, aiohttp, fetch)
2. Database connections (pymysql, psycopg2, pymongo, redis, elasticsearch, etc.)
3. Message queues (kafka, rabbitmq, celery, SQS, etc.)
4. Cloud services (AWS boto3, Google Cloud, Azure, etc.)
5. Email/SMS (smtplib, twilio, sendgrid, etc.)
6. WebSocket connections
7. gRPC calls
8. External file operations (FTP, SFTP, S3, etc.)
9. Socket connections
10. Third-party API SDKs
"""

import ast
import re
import os
from typing import List, Dict, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class OutboundType(Enum):
    """Các loại outbound calls"""
    HTTP_REQUEST = "http_request"
    DATABASE = "database"
    MESSAGE_QUEUE = "message_queue"
    CLOUD_SERVICE = "cloud_service"
    EMAIL_SMS = "email_sms"
    WEBSOCKET = "websocket"
    GRPC = "grpc"
    FILE_TRANSFER = "file_transfer"
    SOCKET = "socket"
    THIRD_PARTY_API = "third_party_api"
    SUBPROCESS = "subprocess"
    DNS_LOOKUP = "dns_lookup"


@dataclass
class OutboundCall:
    """Thông tin về một outbound call được phát hiện"""
    type: OutboundType
    line_number: int
    code_snippet: str
    module: str
    function: str
    description: str
    risk_level: str = "medium"  # low, medium, high, critical


@dataclass
class HandlerAnalysisResult:
    """Kết quả phân tích một handler"""
    handler_name: str
    file_path: str
    has_outbound: bool
    outbound_calls: List[OutboundCall] = field(default_factory=list)
    total_outbound_count: int = 0
    outbound_types: Set[OutboundType] = field(default_factory=set)
    warnings: List[str] = field(default_factory=list)


# ============================================================================
# OUTBOUND PATTERNS CONFIGURATION
# ============================================================================

# HTTP/HTTPS Request patterns
HTTP_PATTERNS = {
    # requests library
    "requests": {
        "functions": ["get", "post", "put", "delete", "patch", "head", "options", "request"],
        "classes": ["Session"],
        "risk": "medium"
    },
    # urllib
    "urllib.request": {
        "functions": ["urlopen", "urlretrieve", "Request"],
        "classes": ["OpenerDirector"],
        "risk": "medium"
    },
    "urllib3": {
        "functions": ["request"],
        "classes": ["PoolManager", "HTTPConnectionPool", "HTTPSConnectionPool"],
        "risk": "medium"
    },
    # httpx (async)
    "httpx": {
        "functions": ["get", "post", "put", "delete", "patch", "head", "options", "request"],
        "classes": ["Client", "AsyncClient"],
        "risk": "medium"
    },
    # aiohttp (async)
    "aiohttp": {
        "functions": [],
        "classes": ["ClientSession", "TCPConnector"],
        "risk": "medium"
    },
    # http.client
    "http.client": {
        "functions": [],
        "classes": ["HTTPConnection", "HTTPSConnection"],
        "risk": "medium"
    },
    # tornado
    "tornado.httpclient": {
        "functions": ["fetch"],
        "classes": ["HTTPClient", "AsyncHTTPClient"],
        "risk": "medium"
    },
    # treq (twisted)
    "treq": {
        "functions": ["get", "post", "put", "delete", "patch", "head"],
        "classes": [],
        "risk": "medium"
    },
}

# Database patterns
DATABASE_PATTERNS = {
    # PostgreSQL
    "psycopg2": {
        "functions": ["connect"],
        "classes": [],
        "risk": "high"
    },
    "psycopg": {
        "functions": ["connect"],
        "classes": ["Connection", "AsyncConnection"],
        "risk": "high"
    },
    "asyncpg": {
        "functions": ["connect", "create_pool"],
        "classes": ["Connection"],
        "risk": "high"
    },
    # MySQL
    "pymysql": {
        "functions": ["connect"],
        "classes": ["Connection"],
        "risk": "high"
    },
    "mysql.connector": {
        "functions": ["connect"],
        "classes": ["MySQLConnection"],
        "risk": "high"
    },
    "aiomysql": {
        "functions": ["connect", "create_pool"],
        "classes": [],
        "risk": "high"
    },
    # SQLite (có thể là local nhưng cũng check)
    "sqlite3": {
        "functions": ["connect"],
        "classes": [],
        "risk": "low"
    },
    # MongoDB
    "pymongo": {
        "functions": [],
        "classes": ["MongoClient"],
        "risk": "high"
    },
    "motor": {
        "functions": [],
        "classes": ["AsyncIOMotorClient"],
        "risk": "high"
    },
    # Redis
    "redis": {
        "functions": [],
        "classes": ["Redis", "StrictRedis", "ConnectionPool"],
        "risk": "high"
    },
    "aioredis": {
        "functions": ["create_redis", "create_redis_pool", "from_url"],
        "classes": ["Redis"],
        "risk": "high"
    },
    # Elasticsearch
    "elasticsearch": {
        "functions": [],
        "classes": ["Elasticsearch", "AsyncElasticsearch"],
        "risk": "high"
    },
    # Cassandra
    "cassandra.cluster": {
        "functions": [],
        "classes": ["Cluster"],
        "risk": "high"
    },
    # SQLAlchemy
    "sqlalchemy": {
        "functions": ["create_engine", "create_async_engine"],
        "classes": ["Engine"],
        "risk": "high"
    },
    # Databases (async)
    "databases": {
        "functions": [],
        "classes": ["Database"],
        "risk": "high"
    },
    # ClickHouse
    "clickhouse_driver": {
        "functions": [],
        "classes": ["Client"],
        "risk": "high"
    },
    # DynamoDB
    "boto3.dynamodb": {
        "functions": [],
        "classes": ["Table"],
        "risk": "high"
    },
    # Memcached
    "pymemcache": {
        "functions": [],
        "classes": ["Client", "HashClient"],
        "risk": "medium"
    },
    # Neo4j
    "neo4j": {
        "functions": [],
        "classes": ["GraphDatabase"],
        "risk": "high"
    },
    # InfluxDB
    "influxdb": {
        "functions": [],
        "classes": ["InfluxDBClient"],
        "risk": "high"
    },
    "influxdb_client": {
        "functions": [],
        "classes": ["InfluxDBClient"],
        "risk": "high"
    },
}

# Message Queue patterns
MESSAGE_QUEUE_PATTERNS = {
    # Kafka
    "kafka": {
        "functions": [],
        "classes": ["KafkaProducer", "KafkaConsumer", "KafkaClient"],
        "risk": "high"
    },
    "confluent_kafka": {
        "functions": [],
        "classes": ["Producer", "Consumer"],
        "risk": "high"
    },
    "aiokafka": {
        "functions": [],
        "classes": ["AIOKafkaProducer", "AIOKafkaConsumer"],
        "risk": "high"
    },
    # RabbitMQ
    "pika": {
        "functions": [],
        "classes": ["BlockingConnection", "SelectConnection"],
        "risk": "high"
    },
    "aio_pika": {
        "functions": ["connect", "connect_robust"],
        "classes": [],
        "risk": "high"
    },
    # Celery
    "celery": {
        "functions": ["send_task"],
        "classes": ["Celery"],
        "risk": "high"
    },
    # AWS SQS
    "boto3.sqs": {
        "functions": ["send_message", "receive_message"],
        "classes": [],
        "risk": "high"
    },
    # Google Pub/Sub
    "google.cloud.pubsub": {
        "functions": [],
        "classes": ["PublisherClient", "SubscriberClient"],
        "risk": "high"
    },
    # Azure Service Bus
    "azure.servicebus": {
        "functions": [],
        "classes": ["ServiceBusClient", "ServiceBusSender"],
        "risk": "high"
    },
    # ZeroMQ
    "zmq": {
        "functions": [],
        "classes": ["Context", "Socket"],
        "risk": "medium"
    },
    # NATS
    "nats": {
        "functions": ["connect"],
        "classes": ["Client"],
        "risk": "high"
    },
    # Redis Pub/Sub (already in redis but specific methods)
    "redis.pubsub": {
        "functions": ["publish", "subscribe"],
        "classes": ["PubSub"],
        "risk": "high"
    },
}

# Cloud Service patterns
CLOUD_PATTERNS = {
    # AWS
    "boto3": {
        "functions": ["client", "resource", "Session"],
        "classes": ["Session"],
        "risk": "high"
    },
    "botocore": {
        "functions": [],
        "classes": ["Session"],
        "risk": "high"
    },
    "aiobotocore": {
        "functions": [],
        "classes": ["AioSession"],
        "risk": "high"
    },
    # Google Cloud
    "google.cloud.storage": {
        "functions": [],
        "classes": ["Client"],
        "risk": "high"
    },
    "google.cloud.bigquery": {
        "functions": [],
        "classes": ["Client"],
        "risk": "high"
    },
    "google.cloud.firestore": {
        "functions": [],
        "classes": ["Client"],
        "risk": "high"
    },
    "google.api_core": {
        "functions": [],
        "classes": [],
        "risk": "high"
    },
    # Azure
    "azure.storage.blob": {
        "functions": [],
        "classes": ["BlobServiceClient", "ContainerClient", "BlobClient"],
        "risk": "high"
    },
    "azure.cosmos": {
        "functions": [],
        "classes": ["CosmosClient"],
        "risk": "high"
    },
    "azure.identity": {
        "functions": [],
        "classes": ["DefaultAzureCredential", "ClientSecretCredential"],
        "risk": "high"
    },
    # Firebase
    "firebase_admin": {
        "functions": ["initialize_app"],
        "classes": [],
        "risk": "high"
    },
    # Supabase
    "supabase": {
        "functions": ["create_client"],
        "classes": ["Client"],
        "risk": "high"
    },
    # Stripe
    "stripe": {
        "functions": [],
        "classes": ["PaymentIntent", "Customer", "Charge"],
        "risk": "critical"
    },
    # Twilio
    "twilio.rest": {
        "functions": [],
        "classes": ["Client"],
        "risk": "high"
    },
}

# Email/SMS patterns
EMAIL_SMS_PATTERNS = {
    # SMTP
    "smtplib": {
        "functions": [],
        "classes": ["SMTP", "SMTP_SSL"],
        "risk": "medium"
    },
    "aiosmtplib": {
        "functions": ["send"],
        "classes": ["SMTP"],
        "risk": "medium"
    },
    # Email libraries
    "sendgrid": {
        "functions": [],
        "classes": ["SendGridAPIClient"],
        "risk": "high"
    },
    "mailgun": {
        "functions": [],
        "classes": [],
        "risk": "high"
    },
    "yagmail": {
        "functions": [],
        "classes": ["SMTP"],
        "risk": "medium"
    },
    "emails": {
        "functions": ["send"],
        "classes": ["Message"],
        "risk": "medium"
    },
    # SMS
    "twilio": {
        "functions": [],
        "classes": ["Client"],
        "risk": "high"
    },
    "vonage": {
        "functions": [],
        "classes": ["Client", "Sms"],
        "risk": "high"
    },
    "nexmo": {
        "functions": [],
        "classes": ["Client"],
        "risk": "high"
    },
    # Push notifications
    "pusher": {
        "functions": [],
        "classes": ["Pusher"],
        "risk": "high"
    },
    "pyapns": {
        "functions": [],
        "classes": ["APNs"],
        "risk": "high"
    },
    "pyfcm": {
        "functions": [],
        "classes": ["FCMNotification"],
        "risk": "high"
    },
}

# WebSocket patterns
WEBSOCKET_PATTERNS = {
    "websocket": {
        "functions": ["create_connection"],
        "classes": ["WebSocket", "WebSocketApp"],
        "risk": "medium"
    },
    "websockets": {
        "functions": ["connect", "serve"],
        "classes": ["WebSocketClientProtocol"],
        "risk": "medium"
    },
    "socketio": {
        "functions": [],
        "classes": ["Client", "AsyncClient", "Server"],
        "risk": "medium"
    },
    "aiohttp.web_ws": {
        "functions": [],
        "classes": ["WebSocketResponse"],
        "risk": "medium"
    },
}

# gRPC patterns
GRPC_PATTERNS = {
    "grpc": {
        "functions": ["insecure_channel", "secure_channel"],
        "classes": ["Channel"],
        "risk": "high"
    },
    "grpcio": {
        "functions": [],
        "classes": [],
        "risk": "high"
    },
}

# File Transfer patterns
FILE_TRANSFER_PATTERNS = {
    # FTP
    "ftplib": {
        "functions": [],
        "classes": ["FTP", "FTP_TLS"],
        "risk": "high"
    },
    "aioftp": {
        "functions": [],
        "classes": ["Client"],
        "risk": "high"
    },
    # SFTP
    "paramiko": {
        "functions": [],
        "classes": ["SSHClient", "SFTPClient", "Transport"],
        "risk": "high"
    },
    "asyncssh": {
        "functions": ["connect"],
        "classes": ["SSHClientConnection"],
        "risk": "high"
    },
    # S3 (file transfer aspect)
    "s3transfer": {
        "functions": [],
        "classes": ["S3Transfer"],
        "risk": "high"
    },
    # rsync via subprocess
    "fabric": {
        "functions": ["run", "sudo", "local"],
        "classes": ["Connection"],
        "risk": "critical"
    },
}

# Socket patterns
SOCKET_PATTERNS = {
    "socket": {
        "functions": ["socket", "create_connection", "getaddrinfo"],
        "classes": ["socket"],
        "risk": "high"
    },
    "asyncio": {
        "functions": ["open_connection", "start_server"],
        "classes": ["StreamReader", "StreamWriter"],
        "risk": "medium"
    },
    "ssl": {
        "functions": ["wrap_socket"],
        "classes": ["SSLSocket", "SSLContext"],
        "risk": "high"
    },
}

# Subprocess patterns (có thể thực hiện network calls)
SUBPROCESS_PATTERNS = {
    "subprocess": {
        "functions": ["run", "call", "Popen", "check_output", "check_call"],
        "classes": ["Popen"],
        "risk": "critical"
    },
    "os": {
        "functions": ["system", "popen", "exec", "execl", "execle", "execlp", "execv", "execve", "execvp", "spawn"],
        "classes": [],
        "risk": "critical"
    },
    "shlex": {
        "functions": ["split"],
        "classes": [],
        "risk": "low"
    },
}

# Third-party API SDKs
THIRD_PARTY_API_PATTERNS = {
    # OpenAI
    "openai": {
        "functions": [],
        "classes": ["OpenAI", "AsyncOpenAI", "ChatCompletion"],
        "risk": "high"
    },
    # Anthropic
    "anthropic": {
        "functions": [],
        "classes": ["Anthropic", "AsyncAnthropic"],
        "risk": "high"
    },
    # Slack
    "slack_sdk": {
        "functions": [],
        "classes": ["WebClient", "AsyncWebClient"],
        "risk": "high"
    },
    "slackclient": {
        "functions": [],
        "classes": ["SlackClient"],
        "risk": "high"
    },
    # Discord
    "discord": {
        "functions": [],
        "classes": ["Client", "Bot"],
        "risk": "high"
    },
    # Telegram
    "telegram": {
        "functions": [],
        "classes": ["Bot"],
        "risk": "high"
    },
    "telethon": {
        "functions": [],
        "classes": ["TelegramClient"],
        "risk": "high"
    },
    # GitHub
    "github": {
        "functions": [],
        "classes": ["Github"],
        "risk": "high"
    },
    # GitLab
    "gitlab": {
        "functions": [],
        "classes": ["Gitlab"],
        "risk": "high"
    },
    # Jira
    "jira": {
        "functions": [],
        "classes": ["JIRA"],
        "risk": "high"
    },
    # Salesforce
    "simple_salesforce": {
        "functions": [],
        "classes": ["Salesforce"],
        "risk": "high"
    },
    # Twitter/X
    "tweepy": {
        "functions": [],
        "classes": ["Client", "API"],
        "risk": "high"
    },
    # LinkedIn
    "linkedin_api": {
        "functions": [],
        "classes": ["Linkedin"],
        "risk": "high"
    },
    # Payment gateways
    "paypalrestsdk": {
        "functions": [],
        "classes": ["Payment"],
        "risk": "critical"
    },
    "square": {
        "functions": [],
        "classes": ["Client"],
        "risk": "critical"
    },
    # Auth providers
    "auth0": {
        "functions": [],
        "classes": ["Auth0"],
        "risk": "high"
    },
    "okta": {
        "functions": [],
        "classes": ["Client"],
        "risk": "high"
    },
    # Analytics
    "mixpanel": {
        "functions": [],
        "classes": ["Mixpanel"],
        "risk": "medium"
    },
    "segment": {
        "functions": [],
        "classes": [],
        "risk": "medium"
    },
    # Datadog
    "datadog": {
        "functions": ["initialize"],
        "classes": ["DogStatsd"],
        "risk": "medium"
    },
    # Sentry
    "sentry_sdk": {
        "functions": ["init", "capture_exception", "capture_message"],
        "classes": [],
        "risk": "medium"
    },
    # GraphQL
    "gql": {
        "functions": [],
        "classes": ["Client"],
        "risk": "high"
    },
    # LangChain (AI)
    "langchain": {
        "functions": [],
        "classes": ["OpenAI", "ChatOpenAI", "Anthropic"],
        "risk": "high"
    },
}

# DNS patterns
DNS_PATTERNS = {
    "socket": {
        "functions": ["gethostbyname", "gethostbyaddr", "getaddrinfo", "getnameinfo"],
        "classes": [],
        "risk": "low"
    },
    "dns.resolver": {
        "functions": ["resolve", "query"],
        "classes": ["Resolver"],
        "risk": "low"
    },
}


# ============================================================================
# AST VISITOR FOR ANALYZING CODE
# ============================================================================

class OutboundCallVisitor(ast.NodeVisitor):
    """AST Visitor để phát hiện outbound calls trong code"""

    def __init__(self, source_lines: List[str]):
        self.source_lines = source_lines
        self.imports: Dict[str, str] = {}  # alias -> module
        self.from_imports: Dict[str, Tuple[str, str]] = {}  # name -> (module, original_name)
        self.outbound_calls: List[OutboundCall] = []
        self.all_patterns = self._build_all_patterns()

    def _build_all_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Tổng hợp tất cả patterns với outbound type"""
        all_patterns = {}

        pattern_configs = [
            (HTTP_PATTERNS, OutboundType.HTTP_REQUEST),
            (DATABASE_PATTERNS, OutboundType.DATABASE),
            (MESSAGE_QUEUE_PATTERNS, OutboundType.MESSAGE_QUEUE),
            (CLOUD_PATTERNS, OutboundType.CLOUD_SERVICE),
            (EMAIL_SMS_PATTERNS, OutboundType.EMAIL_SMS),
            (WEBSOCKET_PATTERNS, OutboundType.WEBSOCKET),
            (GRPC_PATTERNS, OutboundType.GRPC),
            (FILE_TRANSFER_PATTERNS, OutboundType.FILE_TRANSFER),
            (SOCKET_PATTERNS, OutboundType.SOCKET),
            (SUBPROCESS_PATTERNS, OutboundType.SUBPROCESS),
            (THIRD_PARTY_API_PATTERNS, OutboundType.THIRD_PARTY_API),
            (DNS_PATTERNS, OutboundType.DNS_LOOKUP),
        ]

        for patterns, outbound_type in pattern_configs:
            for module, config in patterns.items():
                if module not in all_patterns:
                    all_patterns[module] = {
                        "functions": set(config.get("functions", [])),
                        "classes": set(config.get("classes", [])),
                        "risk": config.get("risk", "medium"),
                        "type": outbound_type
                    }
                else:
                    all_patterns[module]["functions"].update(config.get("functions", []))
                    all_patterns[module]["classes"].update(config.get("classes", []))

        return all_patterns

    def _get_code_snippet(self, lineno: int) -> str:
        """Lấy đoạn code tại dòng cụ thể"""
        if 0 < lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def visit_Import(self, node: ast.Import) -> None:
        """Xử lý import statements"""
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.imports[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Xử lý from ... import statements"""
        module = node.module or ""
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.from_imports[name] = (module, alias.name)
        self.generic_visit(node)

    def _check_call_pattern(self, module: str, name: str, lineno: int) -> Optional[OutboundCall]:
        """Kiểm tra xem call có match với pattern outbound không"""
        # Kiểm tra exact module match
        if module in self.all_patterns:
            pattern = self.all_patterns[module]
            if name in pattern["functions"] or name in pattern["classes"]:
                return OutboundCall(
                    type=pattern["type"],
                    line_number=lineno,
                    code_snippet=self._get_code_snippet(lineno),
                    module=module,
                    function=name,
                    description=f"Outbound call via {module}.{name}",
                    risk_level=pattern["risk"]
                )

        # Kiểm tra partial module match (e.g., "boto3" matches "boto3.client")
        for pattern_module, pattern in self.all_patterns.items():
            if module.startswith(pattern_module + ".") or pattern_module.startswith(module + "."):
                if name in pattern["functions"] or name in pattern["classes"]:
                    return OutboundCall(
                        type=pattern["type"],
                        line_number=lineno,
                        code_snippet=self._get_code_snippet(lineno),
                        module=module,
                        function=name,
                        description=f"Outbound call via {module}.{name}",
                        risk_level=pattern["risk"]
                    )

        return None

    def visit_Call(self, node: ast.Call) -> None:
        """Xử lý function/method calls"""
        lineno = node.lineno

        # Case 1: Direct function call - func()
        if isinstance(node.func, ast.Name):
            func_name = node.func.id

            # Check if it's from a from_import
            if func_name in self.from_imports:
                module, original_name = self.from_imports[func_name]
                call = self._check_call_pattern(module, original_name, lineno)
                if call:
                    self.outbound_calls.append(call)

        # Case 2: Attribute call - module.func() or obj.method()
        elif isinstance(node.func, ast.Attribute):
            attr_name = node.func.attr

            # Get the full attribute chain
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value

            if isinstance(current, ast.Name):
                parts.append(current.id)

            parts.reverse()

            if len(parts) >= 2:
                base = parts[0]
                method = parts[-1]

                # Check if base is an imported module
                if base in self.imports:
                    module = self.imports[base]
                    full_module = ".".join([module] + parts[1:-1]) if len(parts) > 2 else module
                    call = self._check_call_pattern(full_module, method, lineno)
                    if call:
                        self.outbound_calls.append(call)

                # Check if base is from a from_import
                elif base in self.from_imports:
                    module, _ = self.from_imports[base]
                    full_module = ".".join([module, base] + parts[1:-1]) if len(parts) > 2 else f"{module}.{base}"
                    call = self._check_call_pattern(full_module, method, lineno)
                    if call:
                        self.outbound_calls.append(call)

                # Check method patterns directly
                else:
                    for pattern_module, pattern in self.all_patterns.items():
                        if method in pattern["functions"] or base in pattern["classes"]:
                            # Additional context-based matching
                            if self._is_likely_outbound_call(base, method, pattern_module):
                                self.outbound_calls.append(OutboundCall(
                                    type=pattern["type"],
                                    line_number=lineno,
                                    code_snippet=self._get_code_snippet(lineno),
                                    module=pattern_module,
                                    function=method,
                                    description=f"Potential outbound call: {base}.{method}",
                                    risk_level=pattern["risk"]
                                ))
                                break

        self.generic_visit(node)

    def _is_likely_outbound_call(self, base: str, method: str, pattern_module: str) -> bool:
        """Heuristic để xác định có phải outbound call không"""
        # Common HTTP methods
        http_methods = {"get", "post", "put", "delete", "patch", "head", "options", "request", "fetch"}
        if method.lower() in http_methods and "session" in base.lower():
            return True

        # Database connection patterns
        db_patterns = {"connect", "execute", "query", "cursor", "commit", "rollback"}
        if method.lower() in db_patterns:
            return True

        # Message sending patterns
        msg_patterns = {"send", "publish", "produce", "emit"}
        if method.lower() in msg_patterns:
            return True

        return False

    def visit_With(self, node: ast.With) -> None:
        """Xử lý with statements (context managers)"""
        for item in node.items:
            if isinstance(item.context_expr, ast.Call):
                self.visit_Call(item.context_expr)
        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        """Xử lý async with statements"""
        for item in node.items:
            if isinstance(item.context_expr, ast.Call):
                self.visit_Call(item.context_expr)
        self.generic_visit(node)

    def visit_Await(self, node: ast.Await) -> None:
        """Xử lý await expressions"""
        if isinstance(node.value, ast.Call):
            self.visit_Call(node.value)
        self.generic_visit(node)


# ============================================================================
# MAIN CHECKER CLASS
# ============================================================================

class HandlerOutboundChecker:
    """
    Kiểm tra Handler có thực hiện outbound calls

    Usage:
        checker = HandlerOutboundChecker()

        # Check a single file
        result = checker.check_file("path/to/handler.py")

        # Check a directory
        results = checker.check_directory("path/to/handlers/")

        # Check code string
        result = checker.check_code(code_string, "my_handler")

        # Generate report
        report = checker.generate_report(results)
    """

    def __init__(self, custom_patterns: Optional[Dict] = None):
        """
        Khởi tạo checker

        Args:
            custom_patterns: Patterns tùy chỉnh bổ sung
        """
        self.custom_patterns = custom_patterns or {}

    def check_code(self, code: str, handler_name: str = "unknown") -> HandlerAnalysisResult:
        """
        Kiểm tra code string có outbound calls

        Args:
            code: Source code string
            handler_name: Tên của handler

        Returns:
            HandlerAnalysisResult với thông tin chi tiết
        """
        result = HandlerAnalysisResult(
            handler_name=handler_name,
            file_path="<string>",
            has_outbound=False
        )

        try:
            tree = ast.parse(code)
            source_lines = code.split('\n')

            visitor = OutboundCallVisitor(source_lines)
            visitor.visit(tree)

            result.outbound_calls = visitor.outbound_calls
            result.has_outbound = len(visitor.outbound_calls) > 0
            result.total_outbound_count = len(visitor.outbound_calls)
            result.outbound_types = set(call.type for call in visitor.outbound_calls)

        except SyntaxError as e:
            result.warnings.append(f"Syntax error in code: {e}")
        except Exception as e:
            result.warnings.append(f"Error analyzing code: {e}")

        return result

    def check_file(self, file_path: str) -> HandlerAnalysisResult:
        """
        Kiểm tra file Python có outbound calls

        Args:
            file_path: Đường dẫn đến file Python

        Returns:
            HandlerAnalysisResult với thông tin chi tiết
        """
        path = Path(file_path)
        handler_name = path.stem

        result = HandlerAnalysisResult(
            handler_name=handler_name,
            file_path=str(path.absolute()),
            has_outbound=False
        )

        if not path.exists():
            result.warnings.append(f"File not found: {file_path}")
            return result

        if path.suffix != '.py':
            result.warnings.append(f"Not a Python file: {file_path}")
            return result

        try:
            code = path.read_text(encoding='utf-8')
            inner_result = self.check_code(code, handler_name)

            result.has_outbound = inner_result.has_outbound
            result.outbound_calls = inner_result.outbound_calls
            result.total_outbound_count = inner_result.total_outbound_count
            result.outbound_types = inner_result.outbound_types
            result.warnings.extend(inner_result.warnings)

        except Exception as e:
            result.warnings.append(f"Error reading file: {e}")

        return result

    def check_directory(self, directory_path: str, recursive: bool = True) -> List[HandlerAnalysisResult]:
        """
        Kiểm tra tất cả files Python trong directory

        Args:
            directory_path: Đường dẫn đến directory
            recursive: Có scan recursive không

        Returns:
            List các HandlerAnalysisResult
        """
        results = []
        path = Path(directory_path)

        if not path.exists():
            return results

        pattern = "**/*.py" if recursive else "*.py"

        for py_file in path.glob(pattern):
            if py_file.is_file():
                result = self.check_file(str(py_file))
                results.append(result)

        return results

    def check_function(self, code: str, function_name: str) -> HandlerAnalysisResult:
        """
        Kiểm tra một function cụ thể trong code

        Args:
            code: Source code string
            function_name: Tên function cần check

        Returns:
            HandlerAnalysisResult cho function đó
        """
        result = HandlerAnalysisResult(
            handler_name=function_name,
            file_path="<string>",
            has_outbound=False
        )

        try:
            tree = ast.parse(code)

            # Tìm function definition
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.name == function_name:
                        # Extract function code
                        func_code = ast.get_source_segment(code, node)
                        if func_code:
                            inner_result = self.check_code(func_code, function_name)
                            result.has_outbound = inner_result.has_outbound
                            result.outbound_calls = inner_result.outbound_calls
                            result.total_outbound_count = inner_result.total_outbound_count
                            result.outbound_types = inner_result.outbound_types
                        break
            else:
                result.warnings.append(f"Function '{function_name}' not found")

        except Exception as e:
            result.warnings.append(f"Error analyzing function: {e}")

        return result

    def generate_report(self, results: List[HandlerAnalysisResult], format: str = "text") -> str:
        """
        Tạo report từ kết quả phân tích

        Args:
            results: List các HandlerAnalysisResult
            format: Định dạng output ("text", "json", "markdown")

        Returns:
            Report string
        """
        if format == "json":
            return self._generate_json_report(results)
        elif format == "markdown":
            return self._generate_markdown_report(results)
        else:
            return self._generate_text_report(results)

    def _generate_text_report(self, results: List[HandlerAnalysisResult]) -> str:
        """Generate plain text report"""
        lines = []
        lines.append("=" * 80)
        lines.append("HANDLER OUTBOUND ANALYSIS REPORT")
        lines.append("=" * 80)
        lines.append("")

        total_handlers = len(results)
        handlers_with_outbound = sum(1 for r in results if r.has_outbound)
        total_calls = sum(r.total_outbound_count for r in results)

        lines.append(f"Summary:")
        lines.append(f"  - Total handlers analyzed: {total_handlers}")
        lines.append(f"  - Handlers with outbound calls: {handlers_with_outbound}")
        lines.append(f"  - Total outbound calls detected: {total_calls}")
        lines.append("")

        for result in results:
            lines.append("-" * 80)
            lines.append(f"Handler: {result.handler_name}")
            lines.append(f"File: {result.file_path}")
            lines.append(f"Has Outbound: {'YES' if result.has_outbound else 'NO'}")

            if result.has_outbound:
                lines.append(f"Total Outbound Calls: {result.total_outbound_count}")
                lines.append(f"Outbound Types: {', '.join(t.value for t in result.outbound_types)}")
                lines.append("")
                lines.append("Detailed Calls:")

                for call in result.outbound_calls:
                    lines.append(f"  Line {call.line_number}: [{call.type.value}] {call.module}.{call.function}")
                    lines.append(f"    Code: {call.code_snippet}")
                    lines.append(f"    Risk: {call.risk_level}")
                    lines.append("")

            if result.warnings:
                lines.append("Warnings:")
                for warning in result.warnings:
                    lines.append(f"  - {warning}")

            lines.append("")

        return "\n".join(lines)

    def _generate_markdown_report(self, results: List[HandlerAnalysisResult]) -> str:
        """Generate markdown report"""
        lines = []
        lines.append("# Handler Outbound Analysis Report\n")

        total_handlers = len(results)
        handlers_with_outbound = sum(1 for r in results if r.has_outbound)
        total_calls = sum(r.total_outbound_count for r in results)

        lines.append("## Summary\n")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Total handlers analyzed | {total_handlers} |")
        lines.append(f"| Handlers with outbound calls | {handlers_with_outbound} |")
        lines.append(f"| Total outbound calls detected | {total_calls} |")
        lines.append("")

        lines.append("## Detailed Results\n")

        for result in results:
            status = "🔴" if result.has_outbound else "🟢"
            lines.append(f"### {status} {result.handler_name}\n")
            lines.append(f"**File:** `{result.file_path}`\n")
            lines.append(f"**Has Outbound:** {'Yes' if result.has_outbound else 'No'}\n")

            if result.has_outbound:
                lines.append(f"**Total Calls:** {result.total_outbound_count}\n")
                lines.append(f"**Types:** {', '.join(f'`{t.value}`' for t in result.outbound_types)}\n")

                lines.append("\n#### Outbound Calls\n")
                lines.append("| Line | Type | Module | Function | Risk |")
                lines.append("|------|------|--------|----------|------|")

                for call in result.outbound_calls:
                    lines.append(f"| {call.line_number} | {call.type.value} | {call.module} | {call.function} | {call.risk_level} |")

                lines.append("")

            if result.warnings:
                lines.append("\n**Warnings:**\n")
                for warning in result.warnings:
                    lines.append(f"- {warning}")
                lines.append("")

        return "\n".join(lines)

    def _generate_json_report(self, results: List[HandlerAnalysisResult]) -> str:
        """Generate JSON report"""
        import json

        data = {
            "summary": {
                "total_handlers": len(results),
                "handlers_with_outbound": sum(1 for r in results if r.has_outbound),
                "total_outbound_calls": sum(r.total_outbound_count for r in results)
            },
            "results": []
        }

        for result in results:
            result_data = {
                "handler_name": result.handler_name,
                "file_path": result.file_path,
                "has_outbound": result.has_outbound,
                "total_outbound_count": result.total_outbound_count,
                "outbound_types": [t.value for t in result.outbound_types],
                "outbound_calls": [
                    {
                        "type": call.type.value,
                        "line_number": call.line_number,
                        "code_snippet": call.code_snippet,
                        "module": call.module,
                        "function": call.function,
                        "description": call.description,
                        "risk_level": call.risk_level
                    }
                    for call in result.outbound_calls
                ],
                "warnings": result.warnings
            }
            data["results"].append(result_data)

        return json.dumps(data, indent=2)


# ============================================================================
# QUICK CHECK FUNCTIONS
# ============================================================================

def has_outbound(code: str) -> bool:
    """
    Quick check: Code có outbound calls không?

    Args:
        code: Source code string

    Returns:
        True nếu có outbound calls
    """
    checker = HandlerOutboundChecker()
    result = checker.check_code(code)
    return result.has_outbound


def get_outbound_calls(code: str) -> List[OutboundCall]:
    """
    Lấy danh sách tất cả outbound calls trong code

    Args:
        code: Source code string

    Returns:
        List các OutboundCall
    """
    checker = HandlerOutboundChecker()
    result = checker.check_code(code)
    return result.outbound_calls


def check_handler_outbound(handler_code: str, handler_name: str = "handler") -> Dict:
    """
    Kiểm tra handler và trả về kết quả dạng dict

    Args:
        handler_code: Source code của handler
        handler_name: Tên handler

    Returns:
        Dict với thông tin chi tiết
    """
    checker = HandlerOutboundChecker()
    result = checker.check_code(handler_code, handler_name)

    return {
        "handler_name": result.handler_name,
        "has_outbound": result.has_outbound,
        "total_calls": result.total_outbound_count,
        "outbound_types": [t.value for t in result.outbound_types],
        "calls": [
            {
                "type": call.type.value,
                "line": call.line_number,
                "code": call.code_snippet,
                "module": call.module,
                "function": call.function,
                "risk": call.risk_level
            }
            for call in result.outbound_calls
        ],
        "warnings": result.warnings
    }


# ============================================================================
# DEMO AND EXAMPLES
# ============================================================================

def demo():
    """Demo các tính năng của module"""

    print("=" * 80)
    print("HANDLER OUTBOUND CHECKER - DEMO")
    print("=" * 80)
    print()

    # Example 1: HTTP Request handler
    http_handler = '''
import requests
from aiohttp import ClientSession

async def fetch_user_data(user_id: str):
    """Handler thực hiện HTTP request"""
    response = requests.get(f"https://api.example.com/users/{user_id}")
    return response.json()

async def async_fetch(url: str):
    async with ClientSession() as session:
        async with session.get(url) as response:
            return await response.json()
'''

    # Example 2: Database handler
    db_handler = '''
import psycopg2
from pymongo import MongoClient
import redis

def get_user_from_db(user_id: str):
    """Handler kết nối database"""
    conn = psycopg2.connect("postgresql://localhost/mydb")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()

def get_from_cache(key: str):
    r = redis.Redis(host='localhost', port=6379)
    return r.get(key)
'''

    # Example 3: Message Queue handler
    mq_handler = '''
from kafka import KafkaProducer
import pika

def send_to_kafka(message: dict):
    """Handler gửi message đến Kafka"""
    producer = KafkaProducer(bootstrap_servers=['localhost:9092'])
    producer.send('my-topic', message)

def send_to_rabbitmq(message: str):
    connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
    channel = connection.channel()
    channel.basic_publish(exchange='', routing_key='hello', body=message)
'''

    # Example 4: Cloud Services handler
    cloud_handler = '''
import boto3
from google.cloud.storage import Client
from azure.storage.blob import BlobServiceClient

def upload_to_s3(bucket: str, key: str, data: bytes):
    """Handler upload file lên S3"""
    s3 = boto3.client('s3')
    s3.put_object(Bucket=bucket, Key=key, Body=data)

def upload_to_gcs(bucket: str, blob_name: str, data: bytes):
    client = Client()
    bucket = client.bucket(bucket)
    blob = bucket.blob(blob_name)
    blob.upload_from_string(data)
'''

    # Example 5: No outbound handler
    local_handler = '''
import json
import os
from typing import Dict

def process_local_data(data: Dict) -> Dict:
    """Handler chỉ xử lý local data"""
    result = {}
    for key, value in data.items():
        result[key.upper()] = str(value)
    return result

def read_config():
    config_path = os.path.join(os.getcwd(), "config.json")
    with open(config_path) as f:
        return json.load(f)
'''

    # Example 6: Third-party API handler
    api_handler = '''
import openai
from slack_sdk import WebClient
from anthropic import Anthropic

async def call_gpt(prompt: str):
    """Handler gọi OpenAI API"""
    client = openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content

def send_slack_message(channel: str, text: str):
    client = WebClient(token="xoxb-...")
    client.chat_postMessage(channel=channel, text=text)
'''

    # Run checks
    checker = HandlerOutboundChecker()

    examples = [
        ("HTTP Request Handler", http_handler),
        ("Database Handler", db_handler),
        ("Message Queue Handler", mq_handler),
        ("Cloud Services Handler", cloud_handler),
        ("Local Processing Handler (No Outbound)", local_handler),
        ("Third-party API Handler", api_handler),
    ]

    results = []
    for name, code in examples:
        result = checker.check_code(code, name)
        results.append(result)

        print(f"\n{'='*60}")
        print(f"Checking: {name}")
        print(f"{'='*60}")
        print(f"Has Outbound: {'YES ⚠️' if result.has_outbound else 'NO ✅'}")

        if result.has_outbound:
            print(f"Total Outbound Calls: {result.total_outbound_count}")
            print(f"Outbound Types: {', '.join(t.value for t in result.outbound_types)}")
            print("\nDetected Calls:")
            for call in result.outbound_calls:
                print(f"  - Line {call.line_number}: [{call.type.value}] {call.module}.{call.function}")
                print(f"    Risk: {call.risk_level}")

    # Generate full report
    print("\n" + "=" * 80)
    print("FULL MARKDOWN REPORT")
    print("=" * 80)
    print(checker.generate_report(results, format="markdown"))


if __name__ == "__main__":
    demo()
