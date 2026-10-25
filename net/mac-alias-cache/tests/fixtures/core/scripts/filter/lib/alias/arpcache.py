    _cache_filename = "/tmp/alias_filter_arp.cache"
            if cls._now - cls._data[macaddr]['last_seen'] > cls._address_ttl:
                current_macs[item[1]] = {'items': [], 'last_seen': cls._now}
