from parsers.hydra_parser import HydraParser


def test_parse_hydra_credentials_found() -> None:
    output = "[22][ssh] host: 10.0.0.2 login: admin password: admin"
    result = HydraParser.parse(output, service="ssh", port=22)

    assert result.status == "credentials_found"
    assert len(result.credentials) == 1
    assert result.credentials[0].username == "admin"
    assert result.credentials[0].password == "admin"


def test_parse_hydra_no_credentials() -> None:
    output = "[STATUS] 1 of 1 target completed, 0 valid password found"
    result = HydraParser.parse(output, service="ssh", port=22)

    assert result.status == "no_valid_credentials"
    assert result.credentials == []
