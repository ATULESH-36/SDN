"""Bounded idle-TTL/LRU state. Expiry and pressure evictions are observable."""
from collections import OrderedDict


class TTLMap:
    def __init__(self, capacity, ttl):
        if capacity < 1 or ttl <= 0:
            raise ValueError("capacity and ttl must be positive")
        self.capacity, self.ttl = capacity, ttl
        self.data = OrderedDict()
        self.expired = self.evicted = 0

    def expire(self, now):
        removed = []
        while self.data and next(iter(self.data.values()))[0] + self.ttl <= now:
            key, (_, value) = self.data.popitem(last=False)
            self.expired += 1
            removed.append((key, value))
        return removed

    def get(self, key, now, default=None, refresh=True):
        entry = self.data.get(key)
        if entry is None:
            return default
        stamp, value = entry
        if stamp + self.ttl <= now:
            del self.data[key]
            self.expired += 1
            return default
        if refresh:
            self.data.move_to_end(key)
            self.data[key] = (now, value)
        return value

    def put(self, key, value, now):
        removed = self.expire(now)
        if key in self.data:
            del self.data[key]
        self.data[key] = (now, value)
        if len(self.data) > self.capacity:
            removed.append(self.data.popitem(last=False))
            self.evicted += 1
        return removed

    def __len__(self):
        return len(self.data)
