import datetime
import hashlib

import requests
from requests_toolbelt.auth.handler import AuthHandler

from aws_request_signer import UNSIGNED_PAYLOAD, AwsRequestSigner
from aws_request_signer.requests import AwsAuth

AWS_REGION = ""
AWS_ACCESS_KEY_ID = "minio"
AWS_SECRET_ACCESS_KEY = "minio123"

URL_PREFIX = "http://127.0.0.1:9000"
URL = f"{URL_PREFIX}/demo/hello_world.txt"


def main() -> None:
    # Demo content for our target file.
    content = b"Hello, World!\n"
    content_hash = hashlib.sha256(content).hexdigest()

    # Create a request signer instance.
    request_signer = AwsRequestSigner(
        AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, "s3"
    )

    #
    # Use AWS request signer to generate authentication headers.
    #

    # The headers we'll provide and want to sign.
    headers = {"Content-Type": "text/plain", "Content-Length": str(len(content))}

    # Add the authentication headers.
    headers.update(request_signer.sign_with_headers("PUT", URL, headers, content_hash))

    # Make the request.
    r = requests.put(URL, headers=headers, data=content)
    r.raise_for_status()

    # Methods without payload (HEAD/GET/DELETE).
    headers = request_signer.sign_with_headers("HEAD", URL)
    r = requests.head(URL, headers=headers)
    r.raise_for_status()
    assert r.headers["content-length"] == str(len(content))

    headers = request_signer.sign_with_headers("GET", URL)
    r = requests.get(URL, headers=headers)
    r.raise_for_status()
    assert r.content == content

    headers = request_signer.sign_with_headers("DELETE", URL)
    r = requests.delete(URL, headers=headers)
    r.raise_for_status()

    #
    # Use AWS request signer to generate a pre-signed URL.
    #

    # The headers we'll provide and want to sign.
    headers = {"Content-Type": "text/plain", "Content-Length": str(len(content))}

    # Generate the pre-signed URL that includes the authentication
    # parameters. Allow the client to determine the contents by
    # settings the content_has to UNSIGNED-PAYLOAD.
    presigned_url = request_signer.presign_url("PUT", URL, headers, UNSIGNED_PAYLOAD)

    # Perform the request.
    r = requests.put(presigned_url, headers=headers, data=content)
    r.raise_for_status()

    # Methods without payload (GET/HEAD/DELETE).
    presigned_url = request_signer.presign_url("HEAD", URL)
    r = requests.head(presigned_url)
    r.raise_for_status()
    assert r.headers["content-length"] == str(len(content))

    presigned_url = request_signer.presign_url("GET", URL)
    r = requests.get(presigned_url)
    r.raise_for_status()
    assert r.content == content

    presigned_url = request_signer.presign_url("DELETE", URL)
    r = requests.delete(presigned_url)
    r.raise_for_status()

    #
    # Use AWS request signer for requests helper to perform requests.
    #

    # Create a requests session and assign auth handler.
    session = requests.Session()
    session.auth = AuthHandler(
        {
            URL_PREFIX: AwsAuth(
                AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, "s3"
            )
        }
    )

    # Perform the request.
    r = session.put(URL, data=content)
    r.raise_for_status()

    #
    # Use AWS request signer to sign an S3 POST policy request.
    #

    # Create a policy, only restricting bucket and expiration.
    expiration = datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(
        minutes=1
    )
    policy = {
        "expiration": expiration.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "conditions": [
            {"bucket": "demo"},
            {"Content-Type": "text/plain"},
            {"key": "hello_world.txt"},
        ],
    }

    # Get the required form fields to use the policy.
    fields = request_signer.sign_s3_post_policy(policy)

    # Post the form data to the bucket endpoint.
    # Set key (filename) to hello_world.txt.
    r = requests.post(
        URL.rsplit("/", 1)[0],
        data={"key": "hello_world.txt", "Content-Type": "text/plain", **fields},
        files={"file": content},
    )
    r.raise_for_status()


if __name__ == "__main__":
    main()
