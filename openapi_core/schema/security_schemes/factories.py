from six import iteritems

from openapi_core.schema.parameters.enums import ParameterLocation

from openapi_core.schema.security_schemes.enums import SecuritySchemeType
from openapi_core.schema.security_schemes.models import SecurityScheme


class SecuritySchemesGenerator(object):
    """Represents an OpenAPI SecurityScheme in a service."""

    def __init__(self, dereferencer, schemas_registry):
        self.dereferencer = dereferencer
        self.schemas_registry = schemas_registry

    def generate(self, security_schemes):
        schemes_deref = self.dereferencer.dereference(security_schemes)
        for scheme_name, scheme in iteritems(schemes_deref):
            security_type = SecuritySchemeType(scheme['type'])
            security_name = scheme.get('name')
            security_in_spec = scheme.get('in')
            security_in = security_in_spec and ParameterLocation(security_in_spec) or None
            http_scheme = scheme.get('scheme')
            bearer_format = scheme.get('bearerFormat')
            flows = None  # TODO flows generator
            open_id_connect_url = scheme.get('openIdConnectUrl')
            yield \
                scheme_name, \
                SecurityScheme(
                    security_type=security_type,
                    security_name=security_name,
                    security_in=security_in,
                    scheme=http_scheme,
                    bearer_format=bearer_format,
                    flows=flows,
                    open_id_connect_url=open_id_connect_url
                )
