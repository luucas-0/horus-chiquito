from parsers.nmap_parser import NmapParser


SAMPLE_XML = """<?xml version=\"1.0\"?>
<nmaprun scanner=\"nmap\" args=\"nmap -Pn 10.0.0.2\" start=\"0\" version=\"7.98\">
  <host>
    <status state=\"up\" reason=\"syn-ack\"/>
    <address addr=\"10.0.0.2\" addrtype=\"ipv4\"/>
    <hostnames><hostname name=\"target\"/></hostnames>
    <ports>
      <port protocol=\"tcp\" portid=\"22\">
        <state state=\"open\" reason=\"syn-ack\"/>
        <service name=\"ssh\" product=\"OpenSSH\" version=\"8.9\"/>
      </port>
    </ports>
  </host>
  <runstats><finished elapsed=\"1.21\"/></runstats>
</nmaprun>
"""


def test_parse_nmap_xml() -> None:
    result = NmapParser.parse(SAMPLE_XML)

    assert result.nmap_version == "7.98"
    assert len(result.hosts) == 1

    host = result.hosts[0]
    assert host.address == "10.0.0.2"
    assert host.status == "up"
    assert host.hostname == "target"

    assert len(host.ports) == 1
    assert host.ports[0].port == 22
    assert host.ports[0].service == "ssh"
    assert host.ports[0].state == "open"
