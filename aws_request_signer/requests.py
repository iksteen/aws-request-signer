import hashlib

import requests.auth

from aws_request_signer import UNSIGNED_PAYLOAD, AwsRequestSigner

__all__ = ["AwsAuth"]


class AwsAuth(requests.auth.AuthBase):
    def __init__(
        self, region: str, access_key_id: str, secret_access_key: str, service: str
    ) -> None:
        """
        Intialize the authentication helper for requests. Use this with the
        auth argument of the requests methods, or assign it to a session's
        auth property.

        :param region: The AWS region to connect to.
        :param access_key_id: The AWS access key id to use for authentication.
        :param secret_access_key: The AWS secret access key to use for authentication.
        :param service: The service to connect to (f.e. `'s3'`).
        """
        self.request_signer = AwsRequestSigner(
            region, access_key_id, secret_access_key, service
        )

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        if isinstance(request.body, bytes):
            content_hash = hashlib.sha256(request.body).hexdigest()
        else:
            content_hash = UNSIGNED_PAYLOAD

        assert isinstance(request.method, str)
        assert isinstance(request.url, str)
        auth_headers = self.request_signer.sign_with_headers(
            request.method, request.url, request.headers, content_hash
        )
        request.headers.update(auth_headers)
        return request
