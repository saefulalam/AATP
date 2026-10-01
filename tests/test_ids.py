import re

import pytest

from aatp.errors import AATPError
from aatp.ids import derive_agent_id

PUB_HEX = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
AGENT_ID = "aatp:ikee37ajz5k56fdv2d6wajdoi3ytehpiwrm5vacyyygwqfkqadma"


def test_V03_agent_id_derivation():
    pub = bytes.fromhex(PUB_HEX)
    assert derive_agent_id(pub) == AGENT_ID


def test_ID001_derive_format():
    out = derive_agent_id(bytes.fromhex(PUB_HEX))
    assert re.fullmatch(r"aatp:[a-z2-7]{52}", out)


@pytest.mark.parametrize("bad", [b"", b"\x00" * 31, b"\x00" * 33, "x" * 32, None, 123])
def test_ID001_reject_bad_key_length(bad):
    with pytest.raises(AATPError) as ei:
        derive_agent_id(bad)
    assert ei.value.code == "ERR_MALFORMED_MESSAGE"
