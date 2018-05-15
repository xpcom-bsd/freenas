from middlewared.rclone.base import BaseRcloneRemote
from middlewared.schema import Int, Str


class OneDriveRcloneRemote(BaseRcloneRemote):
    name = "ONEDRIVE"
    title = "Microsoft OneDrive"

    rclone_type = "onedrive"

    credentials_schema = [
        Str("token", verbose="Access Token", required=True),
    ]
