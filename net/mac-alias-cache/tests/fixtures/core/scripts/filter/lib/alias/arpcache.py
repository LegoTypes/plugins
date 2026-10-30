    _cache_filename = "/tmp/alias_filter_arp.cache"
    _address_ttl = 43200
        cls._data.update(cls.current_cache())
            if cls._now - cls._data[macaddr]['last_seen'] > cls._address_ttl:
            ['/usr/local/opnsense/scripts/interfaces/list_hosts.py', '-n'],
        for item in hosts.get('rows', []):
                current_macs[item[1]] = {'items': [], 'last_seen': cls._now}
            current_macs[item[1]]['items'].append(item[2])
