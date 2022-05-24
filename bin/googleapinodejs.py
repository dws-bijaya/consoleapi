from contextlib import contextmanager
import tempfile
import subprocess
import json
from django.conf import settings
import os


class googleapinodejs:
    pass

    @contextmanager
    def tempdir(dirname, prefix, suffix):
        path = tempfile.mktemp(dir=dirname, prefix=prefix, suffix=suffix)
        try:
            yield path
        finally:
            try:
                os.remove(path)
                pass
            except IOError:
                pass

    @classmethod
    def exec_index(self, token, urls, update_mode):
        errno, errmsg, data = 0, '+OK', None
        with self.tempdir(dirname=settings.TMP_DIR, prefix='service_account_', suffix=".json") as token_file:
            with self.tempdir(dirname=settings.TMP_DIR, prefix='urls_', suffix='.csv') as urls_file:
                with open(token_file, 'w') as tptr:
                    tptr.write(token)
                with open(urls_file, 'w') as uptr:
                    uptr.write("\\n".join(list(urls)))
                cmd = [settings.NODEJS_BIN]
                cmd.extend(
                    [settings.GGOGLE_INDEXAPI_JS, token_file, urls_file, update_mode])

                try:
                    my_env = os.environ.copy()
                    my_env['NODE_PATH'] = settings.NODE_PATH
                    process = subprocess.Popen(
                        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=my_env)
                    stdout, stderr = process.communicate()
                    stdout, stderr = stdout.decode(), stderr.decode()
                    # exit([stderr.decode(), stdout])
                    errno, errmsg, data = (1, stderr, None) if stderr else (
                        0, '+OK', stdout)
                except Exception as e:
                    errno, errmsg, data = 0, repr(e), None

        return {"errno": errno, "errmsg": errmsg, "data": data}
