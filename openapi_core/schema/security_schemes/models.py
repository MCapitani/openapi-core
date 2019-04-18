from openapi_core.schema.parameters.enums import ParameterLocation

from openapi_core.schema.security_schemes.enums import SecuritySchemeType


class SecurityScheme(object):
    """Representes an OpenAPI SecurityScheme in a service"""

    def __init__(
            self,
            security_type,
            security_name=None,
            security_in=None,
            scheme=None,
            bearer_format=None,
            flows=None,
            open_id_connect_url=None
    ):
        self.security_type = security_type
        self.security_name = security_name
        self.security_in = security_in
        self.scheme = scheme
        self.bearer_format = bearer_format
        self.flows = flows and dict(flows) or {}
        self.open_id_connect_url = open_id_connect_url
        self.validate()

    def validate_api_key(self):
        if self.security_name is None:
            raise ValueError('Illegal api key security scheme: "name" required')
        if self.security_in is None:
            raise ValueError('Illegal api key security scheme: "in" required')
        if self.security_in == ParameterLocation.PATH:
            raise ValueError('Illegal api key security scheme: illegal value for "in": {}'.format(self.security_in))
        if self.scheme is not None:
            raise ValueError('Illegal api key security scheme: "scheme" parameter not supported')
        if self.bearer_format is not None:
            raise ValueError('Illegal api key security scheme: "bearer_format" parameter not supported')
        if self.flows != {}:
            raise ValueError('Illegal api key security scheme: "flows" parameter not supported')
        if self.open_id_connect_url is not None:
            raise ValueError('Illegal api key security scheme: "open_id_connect_url" parameter not supported')

    def validate(self):
        if self.security_type == SecuritySchemeType.API_KEY:
            self.validate_api_key()
        else:
            raise ValueError('Not supported: SecurityScheme type {}'.format(self.security_type))