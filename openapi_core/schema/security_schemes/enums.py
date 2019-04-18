from enum import Enum


class SecuritySchemeType(Enum):

    API_KEY = 'apiKey'
    HTTP = 'http'
    OAUTH2 = 'oauth2'
    OPEN_ID_CONNECT = 'openIdConnect'

    @classmethod
    def has_value(cls, value):
        return any(value == item.value for item in cls)