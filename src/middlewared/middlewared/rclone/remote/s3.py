import boto3

from middlewared.rclone.base import BaseRcloneRemote
from middlewared.schema import Str


class S3RcloneRemote(BaseRcloneRemote):
    name = "S3"
    title = "Amazon S3"

    rclone_type = "s3"

    credentials_schema = [
        Str("access_key_id", verbose="Access Key ID", required=True),
        Str("secret_access_key", verbose="Secret Access Key", required=True),
        Str("endpoint", verbose="Endpoint URL", required=False),
    ]

    def _get_client(self, credentials):
        client = boto3.client(
            "s3",
            endpoint_url=credentials.get("endpoint", "").strip() or None,
            aws_access_key_id=credentials.get("access_key"),
            aws_secret_access_key=credentials.get("secret_key"),
        )
        return client

    async def pre_save_task(self, credentials, attributes, verrors):
        if attributes.get("encryption") not in (None, "AES256"):
            verrors.add("encryption", 'Encryption should be null or "AES256"')

        response = await self.middleware.run_in_io_thread(self._get_client(credentials).get_bucket_location,
                                                          Bucket=attributes["bucket"])
        attributes["region"] = response["LocationConstraint"]

    def get_remote_extra(self, credentials, attributes):
        return dict(server_side_encryption=attributes.get("encryption"))
