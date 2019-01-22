import datetime
import hashlib
import hmac
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from typing import Dict, Optional, Tuple, List, Mapping

__all__ = ["AwsRequestSigner", "UNSIGNED_PAYLOAD"]

UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD"

CredentialScope = Tuple[str, str, str, str]


class AwsRequestSigner:
    algorithm = "AWS4-HMAC-SHA256"

    def __init__(self, region: str, access_key_id: str, secret_access_key: str) -> None:
        """
        Create a new instance of the AwsRequestSigner.

        Use the sign_with_headers method to sign a request and get the
        authenication headers returned.

        Use the presign_url method to add the authentication query
        arguments to an existing URL.

        :param region: The AWS region to connect to.
        :param access_key_id: The AWS access key id to use for authentication.
        :param secret_access_key: The AWS secret access key to use for authentication.
        """

        self.region = region
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key

    def _get_credential_scope(self, timestamp: str, service: str) -> CredentialScope:
        """
        Internal method. Generates a credential scope containing a datestamp, the region,
        the service and a marker.

        :param timestamp: The timestamp on which day the credential is
            valid. Should be in RFC1123Z format (20190122T170000Z) or just
            yyyymmdd.
        :param service: The service to connect to (f.e. `'s3'`).
        :return: A tuple containing the aforementioned credential scope.
        """
        return (timestamp[:8], self.region, service, "aws4_request")

    def _get_canonical_headers(
        self, host: str, headers: Mapping[str, str]
    ) -> List[Tuple[str, str]]:
        """
        Get the canonical header representation for a host and a set of
        headers. This inserts the host header, lowercases all the provided
        header names and sorts them by codepoint.

        :param host: The host you will connect to. Used to generate a
            Host header.
        :param headers: A dictionary of headers.
        :return: The canonical header represenation as a list of key, value
            tuples.
        """
        return sorted(
            {
                "host": host,
                **{key.lower(): value for key, value in headers.items()},
            }.items()
        )

    def _get_signed_headers(self, headers: List[Tuple[str, str]]) -> str:
        """
        Get the signed headers representation of a set of canonical headers.

        :param headers: The canonical headers as returned by
            _get_canonical_headers.
        :return: The signed headers value.
        """
        return ";".join([key for key, _ in headers])

    def _get_request_signature(
        self,
        method: str,
        path: str,
        query: List[Tuple[str, str]],
        headers: List[Tuple[str, str]],
        signed_headers: str,
        content_hash: str,
        timestamp: str,
        credential_scope: CredentialScope,
    ) -> str:
        """
        Generate a signature for a given request.

        :param method: The request method.
        :param path: The request path.
        :param query: The request's query string.
        :param headers: The request's canonical headers.
        :param signed_headers: The request's signed header list.
        :param content_hash: The has of the request's body or
            UNSIGNED_PAYLOAD.
        :param timestamp: The timestamp to apply to the signature.
        :param credential_scope: The credential scope as returned by
            _get_credential_scope.
        :return: The signature for the request.
        """
        canonical_query = urlencode(sorted(query))

        canonical_request = "\n".join(
            (
                method,
                path,
                canonical_query,
                "\n".join(f"{key}:{value}" for key, value in headers),
                "",  # Extra newline after canonical headers.
                signed_headers,
                content_hash,
            )
        )

        string_to_sign = "\n".join(
            (
                self.algorithm,
                timestamp,
                "/".join(credential_scope),
                hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
            )
        )

        signing_key = ("AWS4" + self.secret_access_key).encode("utf8")
        for element in credential_scope:
            signing_key = hmac.new(
                signing_key, element.encode("utf-8"), hashlib.sha256
            ).digest()

        signature = hmac.new(
            signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        return signature

    def sign_with_headers(
        self,
        service: str,
        method: str,
        url: str,
        headers: Optional[Mapping[str, str]] = None,
        content_hash: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Get the required signature headers to perform a signed request.

        :param service: The service to connect to (f.e. `'s3'`).
        :param method: The request method to use.
        :param url: The full URL to access.
        :param headers: Any request headers you want to sign as well.
        :param content_hash: The SHA256 hash of the request body or
            `UNSIGNED_PAYLOAD`. Can be `None` if performing a GET request.
        :return: A dictionary containing the headers required to sign this
            request.
        """
        parsed_url = urlsplit(url)

        if headers is None:
            headers = {}

        if content_hash is None:
            if method == "GET":
                content_hash = hashlib.sha256(b"").hexdigest()
            else:
                raise ValueError(
                    "content_hash must be specified for {} request".format(method)
                )

        timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

        extra_headers = {"x-amz-content-sha256": content_hash, "x-amz-date": timestamp}

        canonical_headers = self._get_canonical_headers(
            parsed_url.netloc, {**headers, **extra_headers}
        )

        signed_headers = self._get_signed_headers(canonical_headers)

        credential_scope = self._get_credential_scope(timestamp, service)

        signature = self._get_request_signature(
            method,
            parsed_url.path,
            parse_qsl(parsed_url.query),
            canonical_headers,
            signed_headers,
            content_hash,
            timestamp,
            credential_scope,
        )

        credential = "/".join((self.access_key_id,) + credential_scope)

        authorization_header = (
            "{algorithm} "
            "Credential={credential}, "
            "SignedHeaders={signed_headers}, "
            "Signature={signature}"
        ).format(
            algorithm=self.algorithm,
            credential=credential,
            signed_headers=signed_headers,
            signature=signature,
        )

        return {**extra_headers, "Authorization": authorization_header}

    def presign_url(
        self,
        service: str,
        method: str,
        url: str,
        headers: Optional[Mapping[str, str]] = None,
        content_hash: Optional[str] = None,
        expires: int = 86400,
    ) -> str:
        """
        Generate a pre-signed URL. These URLs contain all the required
        signature parameters in the query string and have controlled
        expiration.

        :param service: The service to connect to (f.e. `'s3'`).
        :param method: The request method to use.
        :param url: The full URL to access.
        :param headers: Any request headers you want to sign as well.
        :param content_hash: The SHA256 hash of the request body or
            `UNSIGNED_PAYLOAD`. Can be `None` if performing a GET request.
        :param expires: The duration (in seconds) the URL should be valid.
            At least 1, at most 604800.
        :return: The URL with the required signature query arguments
            appended.
        """
        parsed_url = urlsplit(url)

        if headers is None:
            headers = {}

        if content_hash is None:
            if method == "GET":
                content_hash = hashlib.sha256(b"").hexdigest()
            else:
                raise ValueError(
                    "content_hash must be specified for {} request".format(method)
                )

        timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

        canonical_headers = self._get_canonical_headers(parsed_url.netloc, headers)

        signed_headers = self._get_signed_headers(canonical_headers)

        credential_scope = self._get_credential_scope(timestamp, service)
        credential = "/".join((self.access_key_id,) + credential_scope)

        query = parse_qsl(parsed_url.query, True)
        query.extend(
            (
                ("X-Amz-Algorithm", self.algorithm),
                ("X-Amz-Content-Sha256", content_hash),
                ("X-Amz-Credential", credential),
                ("X-Amz-Date", timestamp),
                ("X-Amz-Expires", str(expires)),
                ("X-Amz-SignedHeaders", signed_headers),
            )
        )

        signature = self._get_request_signature(
            method,
            parsed_url.path,
            query,
            canonical_headers,
            signed_headers,
            content_hash,
            timestamp,
            credential_scope,
        )

        query.append(("X-Amz-Signature", signature))
        return urlunsplit(
            (
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                urlencode(query),
                parsed_url.fragment,
            )
        )
