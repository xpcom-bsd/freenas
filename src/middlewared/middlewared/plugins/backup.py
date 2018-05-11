from azure.storage import CloudStorageAccount
from google.cloud import storage

from middlewared.rclone.base import BaseRcloneRemote
from middlewared.schema import accepts, Bool, Dict, Int, Patch, Ref, Str
from middlewared.service import (
    CallError, CRUDService, Service, ValidationErrors, item_method, filterable, job, private
)
from middlewared.utils import load_modules, load_classes, Popen, run

import asyncio
import base64
import boto3
import codecs
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Counter
import errno
import json
import os
import shutil
import subprocess
import re
import requests
import tempfile

CHUNK_SIZE = 5 * 1024 * 1024

REMOTES = {}


class RcloneConfig:
    def __init__(self, credentials):
        #self.provider = provider
        self.credentials = credentials
        #self.attributes = attributes

        self.tmp_file = None
        self.path = None

    async def __aenter__(self):
        self.tmp_file = tempfile.NamedTemporaryFile(mode='w+')

        # Make sure only root can read it as there is sensitive data
        os.chmod(self.tmp_file.name, 0o600)

        # config = dict(self.attributes, **REMOTES[self.provider].get_remote_extra(self.credentials, self.attributes))

        config = dict(self.credentials["attributes"], type=REMOTES[self.credentials["provider"]].rclone_type)

        self.tmp_file.write("[remote]\n")
        for k, v in config.items():
            self.tmp_file.write(f"{k} = {v}\n")

        self.tmp_file.flush()

        return self.tmp_file.name

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.tmp_file:
            self.tmp_file.close()


async def rclone(job, backup, config):
    # Use a temporary file to store rclone file
    with tempfile.NamedTemporaryFile(mode='w+') as f:
        # Make sure only root can read it as there is sensitive data
        os.chmod(f.name, 0o600)

        remote_path = 'remote:{}{}'.format(
            backup['attributes']['bucket'],
            '/{}'.format(backup['attributes']['folder']) if backup['attributes'].get('folder') else '',
        )

        if backup["encryption"]:
            f.write("[encrypted]\n")
            f.write("type = crypt\n")
            f.write("remote = %s\n" % remote_path)
            f.write("filename_encryption = %s\n" % ("standard" if backup["filename_encryption"] else "off"))
            f.write("password = %s\n" % rclone_encrypt_password(backup["encryption_password"]))
            f.write("password2 = %s\n" % rclone_encrypt_password(backup["encryption_salt"]))

            remote_path = "encrypted:/"

        f.write("[remote]\n")
        for k, v in config.items():
            f.write(f"{k} = {v}\n")

        f.flush()

        args = [
            '/usr/local/bin/rclone',
            '--config', f.name,
            '-v',
            '--stats', '1s',
            backup['transfer_mode'].lower(),
        ]

        if backup['direction'] == 'PUSH':
            args.extend([backup['path'], remote_path])
        else:
            args.extend([remote_path, backup['path']])

        proc = await Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        check_task = asyncio.ensure_future(rclone_check_progress(job, proc))
        await proc.wait()
        if proc.returncode != 0:
            await asyncio.wait_for(check_task, None)
            raise ValueError("rclone failed")
        return True


async def rclone_check_progress(job, proc):
    RE_TRANSF = re.compile(r'Transferred:\s*?(.+)$', re.S)
    while True:
        read = (await proc.stdout.readline()).decode()
        job.logs_fd.write(read.encode("utf-8", "ignore"))
        if read == '':
            break
        reg = RE_TRANSF.search(read)
        if reg:
            transferred = reg.group(1).strip()
            if not transferred.isdigit():
                job.set_progress(None, transferred)


def rclone_encrypt_password(password):
    key = bytes([0x9c, 0x93, 0x5b, 0x48, 0x73, 0x0a, 0x55, 0x4d,
                 0x6b, 0xfd, 0x7c, 0x63, 0xc8, 0x86, 0xa9, 0x2b,
                 0xd3, 0x90, 0x19, 0x8e, 0xb8, 0x12, 0x8a, 0xfb,
                 0xf4, 0xde, 0x16, 0x2b, 0x8b, 0x95, 0xf6, 0x38])

    iv = Random.new().read(AES.block_size)
    counter = Counter.new(128, initial_value=int(codecs.encode(iv, "hex"), 16))
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    encrypted = iv + cipher.encrypt(password.encode("utf-8"))
    return base64.urlsafe_b64encode(encrypted).decode("ascii").rstrip("=")


class BackupCredentialService(CRUDService):

    class Config:
        namespace = 'backup.credential'

    @filterable
    async def query(self, filters=None, options=None):
        return await self.middleware.call('datastore.query', 'system.cloudcredentials', filters, options)

    @accepts(Dict(
        'backup-credential',
        Str('name'),
        Str('provider'),
        Dict('attributes', additional_attrs=True),
        register=True,
    ))
    async def do_create(self, data):
        self._validate("backup-credential", data)

        return await self.middleware.call(
            'datastore.insert',
            'system.cloudcredentials',
            data,
        )

    @accepts(Int('id'), Ref('backup-credential'))
    async def do_update(self, id, data):
        self._validate("backup-credential", data)

        return await self.middleware.call(
            'datastore.update',
            'system.cloudcredentials',
            id,
            data,
        )

    @accepts(Int('id'))
    async def do_delete(self, id):
        return await self.middleware.call(
            'datastore.delete',
            'system.cloudcredentials',
            id,
        )

    def _validate(self, schema_name, data):
        verrors = ValidationErrors()

        if data["provider"] not in REMOTES:
            verrors.add(f"{schema_name}.provider", "Invalid provider")
        else:
            schema = Dict(f"{schema_name}.attributes", **REMOTES[data["provider"]].credentials_schema)
            try:
                schema.validate(data["attributes"])
            except ValidationErrors as e:
                verrors.extend(e)

        if verrors:
            raise verrors


class BackupService(CRUDService):

    class Config:
        datastore = 'tasks.cloudsync'
        datastore_extend = 'backup._extend'

    @private
    async def _extend(self, backup):
        backup['encryption_password'] = await self.middleware.call('notifier.pwenc_decrypt',
                                                                   backup['encryption_password'])
        backup['encryption_salt'] = await self.middleware.call('notifier.pwenc_decrypt', backup['encryption_salt'])

        return backup

    @private
    async def _compress(self, backup):
        if 'encryption_password' in backup:
            backup['encryption_password'] = await self.middleware.call('notifier.pwenc_encrypt',
                                                                       backup['encryption_password'])
        if 'encryption_salt' in backup:
            backup['encryption_salt'] = await self.middleware.call('notifier.pwenc_encrypt', backup['encryption_salt'])

        return backup

    @private
    async def _get_backup(self, id):
        return await self.middleware.call('datastore.query', 'tasks.cloudsync', [('id', '=', id)], {'get': True})

    @private
    async def _get_credential(self, credential_id):
        return await self.middleware.call('datastore.query', 'system.cloudcredentials', [('id', '=', credential_id)],
                                          {'get': True})

    @private
    async def _validate(self, verrors, name, data):
        if data['encryption']:
            if not data['encryption_password']:
                verrors.add(f'{name}.encryption_password', 'This field is required when encryption is enabled')

            if not data['encryption_salt']:
                verrors.add(f'{name}.encryption_salt', 'This field is required when encryption is enabled')

        credential = await self._get_credential(data['credential'])

        attributes_verrors = ValidationErrors()
        await REMOTES[credential["provider"]].pre_save_task(credential, data["attributes"], attributes_verrors)
        verrors.add_child(f"{name}.attributes", attributes_verrors)

    @accepts(Dict(
        'backup',
        Str('description'),
        Str('direction', enum=['PUSH', 'PULL']),
        Str('transfer_mode', enum=['SYNC', 'COPY', 'MOVE']),
        Str('path'),
        Int('credential'),
        Bool('encryption', default=False),
        Bool('filename_encryption', default=False),
        Str('encryption_password'),
        Str('encryption_salt'),
        Str('minute'),
        Str('hour'),
        Str('daymonth'),
        Str('dayweek'),
        Str('month'),
        Dict('attributes', additional_attrs=True),
        Bool('enabled', default=True),
        register=True,
    ))
    async def do_create(self, backup):
        """
        Creates a new backup entry.

        .. examples(websocket)::

          Create a new backup using amazon s3 attributes, which is supposed to run every hour.

            :::javascript
            {
              "id": "6841f242-840a-11e6-a437-00e04d680384",
              "msg": "method",
              "method": "backup.create",
              "params": [{
                "description": "s3 sync",
                "path": "/mnt/tank",
                "credential": 1,
                "minute": "00",
                "hour": "*",
                "daymonth": "*",
                "month": "*",
                "attributes": {
                  "bucket": "mybucket",
                  "folder": ""
                },
                "enabled": true
              }]
            }
        """

        verrors = ValidationErrors()

        await self._validate(verrors, 'backup', backup)

        if verrors:
            raise verrors

        backup = await self._compress(backup)

        pk = await self.middleware.call('datastore.insert', 'tasks.cloudsync', backup)
        await self.middleware.call('notifier.restart', 'cron')
        return pk

    @accepts(Int('id'), Patch('backup', 'backup_update', ('attr', {'update': True})))
    async def do_update(self, id, data):
        """
        Updates the backup entry `id` with `data`.
        """
        backup = await self._get_backup(id)

        # credential is a foreign key for now
        if backup['credential']:
            backup['credential'] = backup['credential']['id']

        backup.update(data)

        verrors = ValidationErrors()

        await self._validate(verrors, 'backup_update', backup)

        if verrors:
            raise verrors

        backup = await self._compress(backup)

        await self.middleware.call('datastore.update', 'tasks.cloudsync', id, backup)
        await self.middleware.call('notifier.restart', 'cron')

        return id

    @accepts(Int('id'))
    async def do_delete(self, id):
        """
        Deletes backup entry `id`.
        """
        await self.middleware.call('datastore.delete', 'tasks.cloudsync', id)
        await self.middleware.call('notifier.restart', 'cron')

    @accepts(Int("credential_id"), Str("path"))
    async def ls(self, credential_id, path):
        credential = await self._get_credential(credential_id)

        async with RcloneConfig(credential) as config:
            proc = await run(["rclone", "--config", config, "lsjson", "remote:" + path.strip("/")], check=False,
                             encoding="utf8")
            if proc.returncode == 0:
                return json.loads(proc.stdout)
            else:
                raise CallError(proc.stderr)

    @item_method
    @accepts(Int('id'))
    @job(lock=lambda args: 'backup:{}'.format(args[-1]), lock_queue_size=1, logs=True)
    async def sync(self, job, id):
        """
        Run the backup job `id`, syncing the local data to remote.
        """

        backup = await self._get_backup(id)

        return await rclone(job, backup)

    @accepts(Int('credential_id'), Str('bucket'), Str('path'))
    async def is_dir(self, credential_id, bucket, path):
        credential = await self.middleware.call('datastore.query', 'system.cloudcredentials',
                                                [('id', '=', credential_id)], {'get': True})
        if not credential:
            raise ValueError("Backup credential not found.")

        return await self._call_provider_method(credential['provider'], 'is_dir', credential_id, bucket, path)


async def setup(middleware):
    for module in load_modules(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.pardir,
                                            "rclone", "remote")):
        for cls in load_classes(module, BaseRcloneRemote, []):
            remote = cls(middleware)
            REMOTES[remote.name] = remote

    REMOTES["BACKBLAZE"] = REMOTES["B2"]
