class BaseRcloneRemote:
    name = NotImplemented
    title = NotImplemented

    readonly = False

    rclone_type = NotImplemented

    credentials_schema = NotImplemented

    def __init__(self, middleware):
        self.middleware = middleware

    async def pre_save(self, credentials, attributes, verrors):
        pass

    def get_remote_extra(self, credentials, attributes):
        return dict()
