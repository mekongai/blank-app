"""
Test và demo HandlerOutboundChecker
"""

from handler_outbound_checker import (
    HandlerOutboundChecker,
    has_outbound,
    get_outbound_calls,
    check_handler_outbound,
    OutboundType
)


def test_quick_check():
    """Test các hàm quick check"""
    print("=" * 80)
    print("TEST 1: Quick Check Functions")
    print("=" * 80)

    # Code có outbound
    code_with_outbound = '''
import requests

def handler():
    response = requests.get("https://api.example.com/data")
    return response.json()
'''

    # Code không có outbound
    code_without_outbound = '''
import json

def handler(data):
    return json.dumps(data)
'''

    print("\n1. has_outbound() function:")
    print(f"   Code with HTTP request: {has_outbound(code_with_outbound)}")  # True
    print(f"   Code without outbound: {has_outbound(code_without_outbound)}")  # False

    print("\n2. get_outbound_calls() function:")
    calls = get_outbound_calls(code_with_outbound)
    for call in calls:
        print(f"   - {call.type.value}: {call.module}.{call.function} at line {call.line_number}")

    print("\n3. check_handler_outbound() function:")
    result = check_handler_outbound(code_with_outbound, "my_http_handler")
    print(f"   Handler: {result['handler_name']}")
    print(f"   Has outbound: {result['has_outbound']}")
    print(f"   Total calls: {result['total_calls']}")
    print(f"   Types: {result['outbound_types']}")


def test_comprehensive_handler():
    """Test handler với nhiều loại outbound"""
    print("\n" + "=" * 80)
    print("TEST 2: Comprehensive Handler Analysis")
    print("=" * 80)

    complex_handler = '''
import requests
import redis
from kafka import KafkaProducer
import boto3
import smtplib
from openai import OpenAI
import subprocess

class ComplexHandler:
    def __init__(self):
        self.redis_client = redis.Redis(host='localhost')
        self.s3_client = boto3.client('s3')
        self.kafka_producer = KafkaProducer(bootstrap_servers=['localhost:9092'])

    def process_request(self, data):
        # Check cache
        cached = self.redis_client.get(data['key'])
        if cached:
            return cached

        # Fetch from external API
        response = requests.post("https://api.example.com/process", json=data)
        result = response.json()

        # Send to Kafka
        self.kafka_producer.send('events', result)

        # Store in S3
        self.s3_client.put_object(Bucket='my-bucket', Key='result.json', Body=str(result))

        # Send notification email
        smtp = smtplib.SMTP('smtp.gmail.com', 587)
        smtp.sendmail('from@email.com', 'to@email.com', 'Process completed')

        # Call AI API
        client = OpenAI()
        ai_response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": str(result)}]
        )

        # Run system command (dangerous!)
        subprocess.run(['curl', 'https://webhook.example.com'], capture_output=True)

        return result
'''

    checker = HandlerOutboundChecker()
    result = checker.check_code(complex_handler, "ComplexHandler")

    print(f"\nHandler: {result.handler_name}")
    print(f"Has Outbound: {'YES' if result.has_outbound else 'NO'}")
    print(f"Total Outbound Calls: {result.total_outbound_count}")
    print(f"\nOutbound Types Found:")
    for t in sorted(result.outbound_types, key=lambda x: x.value):
        print(f"  - {t.value}")

    print(f"\nDetailed Calls (sorted by risk):")
    sorted_calls = sorted(result.outbound_calls, key=lambda x: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3}[x.risk_level],
        x.line_number
    ))

    for call in sorted_calls:
        risk_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[call.risk_level]
        print(f"  {risk_emoji} Line {call.line_number}: [{call.risk_level.upper()}] {call.type.value}")
        print(f"     Module: {call.module}.{call.function}")
        print(f"     Code: {call.code_snippet[:60]}...")


def test_different_handler_types():
    """Test các loại handler khác nhau"""
    print("\n" + "=" * 80)
    print("TEST 3: Different Handler Types")
    print("=" * 80)

    handlers = {
        "HTTP Handler": '''
import httpx
import aiohttp

async def http_handler():
    async with httpx.AsyncClient() as client:
        r = await client.get("https://api.example.com")
    async with aiohttp.ClientSession() as session:
        async with session.get("https://api.example.com") as resp:
            return await resp.json()
''',
        "Database Handler": '''
import psycopg2
from pymongo import MongoClient
from elasticsearch import Elasticsearch

def db_handler():
    pg_conn = psycopg2.connect("postgresql://localhost/db")
    mongo_client = MongoClient("mongodb://localhost:27017")
    es_client = Elasticsearch(["localhost:9200"])
    return {"pg": pg_conn, "mongo": mongo_client, "es": es_client}
''',
        "Message Queue Handler": '''
from kafka import KafkaProducer
import pika
from celery import Celery

def mq_handler(message):
    producer = KafkaProducer()
    producer.send("topic", message)

    connection = pika.BlockingConnection()
    channel = connection.channel()
    channel.basic_publish(exchange='', routing_key='queue', body=message)

    app = Celery()
    app.send_task("task_name", args=[message])
''',
        "Pure Local Handler": '''
import json
import hashlib
from datetime import datetime

def local_handler(data):
    # No outbound calls - pure local processing
    processed = {
        "timestamp": datetime.now().isoformat(),
        "hash": hashlib.md5(json.dumps(data).encode()).hexdigest(),
        "data": data
    }
    return json.dumps(processed)
''',
    }

    checker = HandlerOutboundChecker()

    for name, code in handlers.items():
        result = checker.check_code(code, name)
        status = "🔴 HAS OUTBOUND" if result.has_outbound else "🟢 NO OUTBOUND"
        print(f"\n{name}: {status}")
        if result.has_outbound:
            types = ", ".join(t.value for t in result.outbound_types)
            print(f"   Types: {types}")
            print(f"   Calls: {result.total_outbound_count}")


def test_async_patterns():
    """Test async handler patterns"""
    print("\n" + "=" * 80)
    print("TEST 4: Async Handler Patterns")
    print("=" * 80)

    async_handler = '''
import asyncio
import aiohttp
import aioredis
import asyncpg
from aiokafka import AIOKafkaProducer

async def async_handler(data):
    # Async HTTP
    async with aiohttp.ClientSession() as session:
        async with session.post("https://api.example.com", json=data) as resp:
            result = await resp.json()

    # Async Redis
    redis = await aioredis.from_url("redis://localhost")
    await redis.set("key", "value")

    # Async PostgreSQL
    conn = await asyncpg.connect("postgresql://localhost/db")
    await conn.fetch("SELECT * FROM users")
    await conn.close()

    # Async Kafka
    producer = AIOKafkaProducer(bootstrap_servers='localhost:9092')
    await producer.start()
    await producer.send_and_wait("topic", b"message")
    await producer.stop()

    return result
'''

    checker = HandlerOutboundChecker()
    result = checker.check_code(async_handler, "AsyncHandler")

    print(f"\nAsync Handler Analysis:")
    print(f"Has Outbound: {result.has_outbound}")
    print(f"Total Calls: {result.total_outbound_count}")
    print(f"\nAsync Outbound Patterns Detected:")
    for call in result.outbound_calls:
        print(f"  - Line {call.line_number}: {call.type.value} - {call.module}")


def test_file_analysis():
    """Test phân tích file"""
    print("\n" + "=" * 80)
    print("TEST 5: File Analysis")
    print("=" * 80)

    checker = HandlerOutboundChecker()

    # Analyze example file
    result = checker.check_file("examples/example_handlers.py")

    print(f"\nFile: {result.file_path}")
    print(f"Has Outbound: {result.has_outbound}")
    print(f"Total Calls: {result.total_outbound_count}")

    if result.has_outbound:
        print(f"\nOutbound Types:")
        for t in result.outbound_types:
            print(f"  - {t.value}")

        print(f"\nTop 10 Calls by Risk:")
        sorted_calls = sorted(
            result.outbound_calls,
            key=lambda x: ({"critical": 0, "high": 1, "medium": 2, "low": 3}[x.risk_level], x.line_number)
        )[:10]

        for call in sorted_calls:
            print(f"  Line {call.line_number}: [{call.risk_level}] {call.type.value} - {call.module}.{call.function}")


def test_report_generation():
    """Test tạo report"""
    print("\n" + "=" * 80)
    print("TEST 6: Report Generation")
    print("=" * 80)

    handlers_code = [
        ("api_handler", '''
import requests
def api_handler():
    return requests.get("https://api.example.com").json()
'''),
        ("db_handler", '''
import psycopg2
def db_handler():
    conn = psycopg2.connect("postgresql://localhost/db")
    return conn.cursor().fetchall()
'''),
        ("local_handler", '''
def local_handler(x):
    return x * 2
'''),
    ]

    checker = HandlerOutboundChecker()
    results = [checker.check_code(code, name) for name, code in handlers_code]

    print("\n--- TEXT REPORT ---")
    print(checker.generate_report(results, format="text"))

    print("\n--- JSON REPORT ---")
    print(checker.generate_report(results, format="json"))


def test_edge_cases():
    """Test edge cases"""
    print("\n" + "=" * 80)
    print("TEST 7: Edge Cases")
    print("=" * 80)

    edge_cases = {
        "Aliased imports": '''
import requests as req
from aiohttp import ClientSession as CS

def handler():
    req.get("https://api.example.com")
    session = CS()
''',
        "Nested calls": '''
import requests
import json

def handler():
    data = json.loads(requests.get("https://api.example.com").text)
    return data
''',
        "Class method calls": '''
from redis import Redis

class Handler:
    def __init__(self):
        self.redis = Redis()

    def process(self):
        return self.redis.get("key")
''',
        "Context managers": '''
import psycopg2

def handler():
    with psycopg2.connect("postgresql://localhost/db") as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
''',
        "Chained calls": '''
import boto3

def handler():
    boto3.client('s3').put_object(Bucket='b', Key='k', Body='data')
''',
    }

    checker = HandlerOutboundChecker()

    for name, code in edge_cases.items():
        result = checker.check_code(code, name)
        print(f"\n{name}:")
        print(f"  Has Outbound: {result.has_outbound}")
        if result.has_outbound:
            for call in result.outbound_calls:
                print(f"  - Line {call.line_number}: {call.module}.{call.function}")


def main():
    """Run all tests"""
    print("\n" + "=" * 80)
    print("HANDLER OUTBOUND CHECKER - TEST SUITE")
    print("=" * 80)

    test_quick_check()
    test_comprehensive_handler()
    test_different_handler_types()
    test_async_patterns()
    test_file_analysis()
    test_report_generation()
    test_edge_cases()

    print("\n" + "=" * 80)
    print("ALL TESTS COMPLETED!")
    print("=" * 80)


if __name__ == "__main__":
    main()
