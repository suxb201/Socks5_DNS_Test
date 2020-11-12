import struct
import random
import toml
import json
from datetime import datetime, timedelta
import time
with open("config.toml", encoding='utf-8') as f:
    config = toml.loads(f.read())
print(config)
x = datetime.now().timestamp()
time.sleep(3)
y = datetime.now().timestamp()
print(y-x)
