import pytest

from openapi_core.schema.parameters.enums import ParameterLocation
from openapi_core.schema.security_schemes.enums import SecuritySchemeType
from openapi_core.schema.security_schemes.models import SecurityScheme
from openapi_core.shortcuts import create_spec


spec_paths = [
    "data/v3.0/security.yaml"
]


class TestSecurity(object):

    @pytest.mark.parametrize("spec_path", spec_paths)
    def test_schemes(self, factory, spec_path):
        spec_dict = factory.spec_from_file(spec_path)
        spec = create_spec(spec_dict)

        schemes = spec.components.security_schemes
        assert len(schemes) == 2

        assert 'key1' in schemes
        key1 = schemes['key1']
        assert isinstance(key1, SecurityScheme)
        assert key1.security_type == SecuritySchemeType.API_KEY
        assert key1.security_name == 'key'
        assert key1.security_in == ParameterLocation.HEADER

        assert 'key2' in schemes
        key2 = schemes['key2']
        assert isinstance(key2, SecurityScheme)
        assert key2.security_type == SecuritySchemeType.API_KEY
        assert key2.security_name == 'key-cookie'
        assert key2.security_in == ParameterLocation.COOKIE

    @pytest.mark.parametrize("spec_path", spec_paths)
    def test_default(self, factory, spec_path):
        spec_dict = factory.spec_from_file(spec_path)
        spec = create_spec(spec_dict)

        assert spec.security == [{'key1': []}]
        assert spec.get('/status').security is None

    @pytest.mark.parametrize("spec_path", spec_paths)
    def test_different(self, factory, spec_path):
        spec_dict = factory.spec_from_file(spec_path)
        spec = create_spec(spec_dict)

        assert spec.get('/status-secure').security == [{'key2': []}]

    @pytest.mark.parametrize("spec_path", spec_paths)
    def test_no_security(self, factory, spec_path):
        spec_dict = factory.spec_from_file(spec_path)
        spec = create_spec(spec_dict)

        assert spec.get('/status-insecure').security == []


if __name__ == '__main__':
    pytest.main([__file__])
