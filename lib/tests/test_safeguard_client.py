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
import json
from io import StringIO

from ..safeguard import SafeguardClient


class StubHttpClient(object):
    def __init__(self, responses={}):
        self.responses = responses

    def make_request(self, url, headers={}, data=None):
        return StringIO(self.responses[url])


def test_get_account_with_different_casing():
    http_client = StubHttpClient({
        'https://the-address/service/core/v2/Me/RequestableAssets': json.dumps([
            {
                'NetworkAddress': None,
                'Name': 'the.asset',
                'Id': 'the-asset-id',
            }
        ]),
        'https://the-address/service/core/v2/Me/RequestableAssets/the-asset-id/Accounts': json.dumps([
            {
                'Name': 'Thomas.Testman',
                'Id': 'the-account-id'
            }
        ]),
    })
    sg_client = SafeguardClient(http_client=http_client, address="the-address", access_token="the-token")
    assert sg_client.get_account(asset_identifier="THE.ASSET", account_name="thomas.testman")
