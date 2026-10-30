        self._filename_alias_hash = '/var/db/aliastables/%s.md5.txt' % self._name
            if self._ttl > 0 and os.path.isfile(self._filename_alias_hash):
                fstat = os.stat(self._filename_alias_hash)
                self._has_expired = fstat.st_mtime > now or now - fstat.st_mtime > self._ttl
