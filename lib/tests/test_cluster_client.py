#
#   Copyright (c) 2019 One Identity
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
from ..safeguard import SafeguardClusterClient
from .conftest import DummySafeguardClient, UnreachableSafeguardClient


def test_cluster_client_uses_first_reachable_node():
    scc = SafeguardClusterClient(
        [
            UnreachableSafeguardClient(),
            DummySafeguardClient(asset_id="2nd_asset_id", account_id="2nd_account_id"),
            DummySafeguardClient(asset_id="3rd_asset_id", account_id="3rd_account_id"),
        ]
    )
    account = scc.get_account(asset_identifier="the_asset", account_name="the_account")
    assert account.asset_id == "2nd_asset_id"
    assert account.id == "2nd_account_id"
