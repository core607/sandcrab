"""Check anonymous GHCR access after an authenticated pull of the same image."""
import json
import sys
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def check(package, tag):
    query = urlencode({'service': 'ghcr.io', 'scope': 'repository:' + package + ':pull'})
    try:
        with urlopen('https://ghcr.io/token?' + query, timeout=20) as response:
            token = json.load(response)['token']
        request = Request('https://ghcr.io/v2/' + package + '/manifests/' + tag, method='HEAD', headers={
            'Authorization': 'Bearer ' + token,
            'Accept': 'application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json',
        })
        with urlopen(request, timeout=20):
            raise RuntimeError('The released image permits an anonymous pull')
    except HTTPError as error:
        if error.code not in (401, 403):
            raise
    print('Anonymous image pull denied')


if __name__ == '__main__':
    check(*sys.argv[1:])
