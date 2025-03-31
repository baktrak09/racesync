import os
import redis
from rq import Worker, Queue, Connection

from app import run_inventory_update  # ✅ Make sure your task is imported
from app import redis_conn  # Use your existing Redis connection

listen = ['default']

if __name__ == '__main__':
    with Connection(redis_conn):
        worker = Worker(map(Queue, listen))
        print("✅ RQ Worker started and listening for jobs...")
        worker.work()
