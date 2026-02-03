"""
Các ví dụ handlers để test với HandlerOutboundChecker
"""

# ============================================================================
# EXAMPLE 1: Handler có nhiều loại outbound calls
# ============================================================================

import requests
import asyncio
from typing import Dict, Any, Optional
import json


class UserServiceHandler:
    """Handler xử lý user service với nhiều outbound calls"""

    def __init__(self, api_url: str, db_connection_string: str):
        self.api_url = api_url
        self.db_connection_string = db_connection_string

    def fetch_user_from_api(self, user_id: str) -> Dict[str, Any]:
        """Gọi external API để lấy user data"""
        response = requests.get(f"{self.api_url}/users/{user_id}")
        response.raise_for_status()
        return response.json()

    def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Tạo user qua API"""
        response = requests.post(f"{self.api_url}/users", json=user_data)
        return response.json()


# ============================================================================
# EXAMPLE 2: Async Handler với database và cache
# ============================================================================

async def async_data_handler(query: str) -> Optional[Dict]:
    """Async handler với database và cache operations"""
    import aioredis
    import asyncpg

    # Check cache first
    redis = await aioredis.from_url("redis://localhost")
    cached = await redis.get(f"query:{query}")

    if cached:
        return json.loads(cached)

    # Query database
    conn = await asyncpg.connect("postgresql://localhost/mydb")
    result = await conn.fetch(query)
    await conn.close()

    # Cache result
    await redis.set(f"query:{query}", json.dumps(result))

    return result


# ============================================================================
# EXAMPLE 3: Handler gửi notifications
# ============================================================================

def notification_handler(user_id: str, message: str) -> bool:
    """Handler gửi notification qua nhiều channels"""
    import smtplib
    from twilio.rest import Client as TwilioClient
    from slack_sdk import WebClient

    success = True

    # Send email
    try:
        smtp = smtplib.SMTP("smtp.gmail.com", 587)
        smtp.starttls()
        smtp.login("user@gmail.com", "password")
        smtp.sendmail("from@email.com", "to@email.com", message)
        smtp.quit()
    except Exception:
        success = False

    # Send SMS via Twilio
    try:
        twilio = TwilioClient("account_sid", "auth_token")
        twilio.messages.create(to="+1234567890", from_="+0987654321", body=message)
    except Exception:
        success = False

    # Send Slack message
    try:
        slack = WebClient(token="xoxb-token")
        slack.chat_postMessage(channel="#notifications", text=message)
    except Exception:
        success = False

    return success


# ============================================================================
# EXAMPLE 4: Handler với Cloud Services
# ============================================================================

def cloud_storage_handler(file_path: str, bucket: str) -> Dict[str, str]:
    """Handler upload file lên nhiều cloud providers"""
    import boto3
    from google.cloud.storage import Client as GCSClient
    from azure.storage.blob import BlobServiceClient

    results = {}

    # Upload to AWS S3
    s3 = boto3.client("s3")
    s3.upload_file(file_path, bucket, file_path.split("/")[-1])
    results["s3"] = f"s3://{bucket}/{file_path}"

    # Upload to Google Cloud Storage
    gcs = GCSClient()
    gcs_bucket = gcs.bucket(bucket)
    blob = gcs_bucket.blob(file_path.split("/")[-1])
    blob.upload_from_filename(file_path)
    results["gcs"] = f"gs://{bucket}/{file_path}"

    # Upload to Azure Blob Storage
    azure_client = BlobServiceClient.from_connection_string("connection_string")
    container = azure_client.get_container_client(bucket)
    with open(file_path, "rb") as data:
        container.upload_blob(file_path.split("/")[-1], data)
    results["azure"] = f"azure://{bucket}/{file_path}"

    return results


# ============================================================================
# EXAMPLE 5: Handler với Message Queue
# ============================================================================

async def message_queue_handler(event: Dict[str, Any]) -> None:
    """Handler publish events đến message queues"""
    from kafka import KafkaProducer
    import pika
    from celery import Celery

    # Kafka
    kafka_producer = KafkaProducer(bootstrap_servers=["localhost:9092"])
    kafka_producer.send("events", json.dumps(event).encode())
    kafka_producer.flush()

    # RabbitMQ
    connection = pika.BlockingConnection(pika.ConnectionParameters("localhost"))
    channel = connection.channel()
    channel.basic_publish(exchange="", routing_key="events", body=json.dumps(event))
    connection.close()

    # Celery task
    app = Celery("tasks", broker="redis://localhost:6379/0")
    app.send_task("process_event", args=[event])


# ============================================================================
# EXAMPLE 6: Handler với AI/ML APIs
# ============================================================================

async def ai_handler(prompt: str) -> Dict[str, str]:
    """Handler gọi các AI APIs"""
    import openai
    from anthropic import Anthropic

    results = {}

    # OpenAI
    openai_client = openai.OpenAI()
    gpt_response = openai_client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    results["openai"] = gpt_response.choices[0].message.content

    # Anthropic Claude
    anthropic_client = Anthropic()
    claude_response = anthropic_client.messages.create(
        model="claude-3-opus-20240229",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}]
    )
    results["anthropic"] = claude_response.content[0].text

    return results


# ============================================================================
# EXAMPLE 7: Handler KHÔNG CÓ outbound (local processing only)
# ============================================================================

def local_processing_handler(data: Dict[str, Any]) -> Dict[str, Any]:
    """Handler chỉ xử lý data locally, không có outbound calls"""
    import hashlib
    from datetime import datetime

    # Process data locally
    result = {
        "processed_at": datetime.now().isoformat(),
        "input_hash": hashlib.sha256(json.dumps(data).encode()).hexdigest(),
        "data": {}
    }

    # Transform data
    for key, value in data.items():
        if isinstance(value, str):
            result["data"][key] = value.upper()
        elif isinstance(value, (int, float)):
            result["data"][key] = value * 2
        else:
            result["data"][key] = value

    return result


def pure_computation_handler(numbers: list) -> Dict[str, float]:
    """Handler tính toán thuần túy"""
    import math
    from statistics import mean, stdev

    return {
        "sum": sum(numbers),
        "mean": mean(numbers),
        "stdev": stdev(numbers) if len(numbers) > 1 else 0,
        "max": max(numbers),
        "min": min(numbers),
        "sqrt_sum": math.sqrt(sum(x**2 for x in numbers))
    }


# ============================================================================
# EXAMPLE 8: Handler với WebSocket
# ============================================================================

async def websocket_handler(message: str):
    """Handler sử dụng WebSocket"""
    import websockets

    async with websockets.connect("wss://example.com/ws") as ws:
        await ws.send(message)
        response = await ws.recv()
        return response


# ============================================================================
# EXAMPLE 9: Handler với gRPC
# ============================================================================

def grpc_handler(request_data: Dict):
    """Handler sử dụng gRPC"""
    import grpc

    channel = grpc.insecure_channel("localhost:50051")
    # stub = some_pb2_grpc.SomeServiceStub(channel)
    # response = stub.SomeMethod(request)
    return {"status": "sent via grpc"}


# ============================================================================
# EXAMPLE 10: Handler với File Transfer (FTP/SFTP)
# ============================================================================

def file_transfer_handler(local_path: str, remote_path: str):
    """Handler transfer files qua FTP/SFTP"""
    from ftplib import FTP
    import paramiko

    # FTP upload
    ftp = FTP("ftp.example.com")
    ftp.login("user", "password")
    with open(local_path, "rb") as f:
        ftp.storbinary(f"STOR {remote_path}", f)
    ftp.quit()

    # SFTP upload
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect("sftp.example.com", username="user", password="password")
    sftp = ssh.open_sftp()
    sftp.put(local_path, remote_path)
    sftp.close()
    ssh.close()


# ============================================================================
# EXAMPLE 11: Handler với subprocess (có thể chạy network commands)
# ============================================================================

def subprocess_handler(command: str):
    """Handler nguy hiểm - chạy subprocess"""
    import subprocess
    import os

    # Subprocess call - có thể thực hiện network operations
    result = subprocess.run(command, shell=True, capture_output=True)

    # Os system call
    os.system(f"ping -c 1 google.com")

    return result.stdout.decode()


if __name__ == "__main__":
    # Test local handlers
    print("Testing local_processing_handler:")
    result = local_processing_handler({"name": "test", "count": 5})
    print(result)

    print("\nTesting pure_computation_handler:")
    result = pure_computation_handler([1, 2, 3, 4, 5])
    print(result)
