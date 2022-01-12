# aws-request-signer
> A python library to sign AWS requests using AWS Signature V4.

This small python library serves only purpose: Helping you sign HTTP
requests for use with AWS (and compatible) services. The library is
unopinionated and should work with just about anything that makes HTTP
requests (requests, aiohttp).

It supports generating authorization headers for HTTP requests,
pre-signing URLs so you can easily use them elsewhere and signing S3
POST policies for use in HTML forms.

This library has no requirements, but comes with an authentication
helper for the requests package.

## Installation

`aws-request-signer` is available from pypi:

```sh
pip install aws-request-signer
```

## Usage example

Here's an example of how to use the library to sign a request to upload a file to a
[minio](https://minio.io/) S3 bucket running on your local machine:

```python
import hashlib

import requests
from aws_request_signer import AwsRequestSigner

AWS_REGION = ""
AWS_ACCESS_KEY_ID = "minio"
AWS_SECRET_ACCESS_KEY = "minio123"

URL = "http://127.0.0.1:9000/demo/hello_world.txt"

# Demo content for our target file.
content = b"Hello, World!\n"
content_hash = hashlib.sha256(content).hexdigest()

# Create a request signer instance.
request_signer = AwsRequestSigner(
    AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, "s3"
)

# The headers we'll provide and want to sign.
headers = {"Content-Type": "text/plain", "Content-Length": str(len(content))}

# Add the authentication headers.
headers.update(
    request_signer.sign_with_headers("PUT", URL, headers, content_hash)
)

# Make the request.
r = requests.put(URL, headers=headers, data=content)
r.raise_for_status()
```

_For more examples and usage, please refer to
[demo.py](https://github.com/iksteen/aws-request-signer/blob/master/demo.py)._

## Development setup

For development purposes, you can clone the repository and use
[poetry](https://poetry.eustace.io/) to install and maintain the
dependencies. There is no test suite. It comes with a set of pre-commit
hooks that can format (isort, black) and check your code (mypy, flake8)
automatically.

```sh
git clone git@github.com:iksteen/aws-request-signer.git
cd aws-request-signer
poetry install -E demo
poetry run pre-commit install
```

## Release History

* 1.1.1
    * Use `quote` instead of the default `quote_plus` so query
      arguments that contain spaces work (thanks @eraser-77).
* 1.1.0
    * Minimum supported python version is now 3.6.1.
    * Assume empty content when signing a HEAD or DELETE request
      just as we do when signing a GET request. Thanks @alvassin!
    * Fix bug where `sign_with_headers` did not include valueless
      query arguments in the signing process (f.e. `?acl`).
* 1.0.0
    * Initial Release.

## Meta

Ingmar Steen – [@iksteen](https://twitter.com/iksteen)

Distributed under the MIT license. See ``LICENSE`` for more information.

[https://github.com/iksteen/](https://github.com/iksteen/)

## Contributing

1. Fork it (<https://github.com/iksteen/aws-request-signer/fork>)
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Create a new Pull Request
