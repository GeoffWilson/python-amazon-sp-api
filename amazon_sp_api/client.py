import datetime
import hashlib
import hmac
import json

from typing import Optional, Dict, List, Type


def _hash_string(string_to_hash: str) -> str:
    return hashlib.sha256(string_to_hash.encode('utf-8')).hexdigest()


class SpApiResponse(object):
    def __init__(self, data: Dict[str, any]):
        if data.get('payload', None) is None:
            raise ValueError('Missing payload key')


class _SpApiRequest(object):
    def __init__(self, client, method, endpoint, response_type):
        self.client = client
        self.method: str = method
        self.endpoint: str = endpoint
        self.query_string: Dict[str, str] = {}
        self.payload: Dict[str, str] = {}
        self._response_type: Type[SpApiResponse] = response_type

    def get_query_string(self) -> str:
        import urllib.parse
        query_keys = list(self.query_string.keys())
        query_keys.sort()
        query_string_parts = []
        for key in query_keys:
            query_string_parts.append(f'{key}={urllib.parse.quote(self.query_string.get(key))}')
        return '&'.join(query_string_parts)

    def payload_as_string(self):
        if self.method == 'GET':
            return ''
        return json.dumps(self.payload)

    def make_response(self, data) -> SpApiResponse:
        return self._response_type(data=data)

    def perform(self):
        raise NotImplementedError('Cant do this')


class AmazonWebServicesCredentials(object):
    def __init__(self, access_key_id: str, secret_key_id: str, role_arn: str):
        self.access_key_id = access_key_id
        self.secret_key_id = secret_key_id
        self.role_arn = role_arn


class LoginWithAmazonCredentials(object):
    def __init__(self, client_id: str, client_secret: str):
        self.client_id = client_id
        self.client_secret = client_secret


class ListOrdersResponse(SpApiResponse):
    def __init__(self, data: Dict[str, any]):
        super().__init__(data)
        payload = data.get('payload', {})
        self.orders: List[Order] = [Order(data=x) for x in payload.get('Orders', [])]


class Client(object):
    AWS_REGION = 'eu-west-1'
    AWS_ALGORITH = 'AWS4-HMAC-SHA256'

    def __init__(
            self,
            refresh_token: str,
            aws_credentials: AmazonWebServicesCredentials,
            lwa_credentials: LoginWithAmazonCredentials
    ):
        self._refresh_token = refresh_token
        self._aws_credentials = aws_credentials
        self._lwa_credentials = lwa_credentials

        self._base_url: str = 'https://sellingpartnerapi-eu.amazon.com'

        self._headers: Dict[str, str] = {}

        # These values are set by the client when required
        self._access_token: Optional[str] = None
        self._access_token_expires: Optional[datetime.datetime] = None
        self._assumed_access_key_id: Optional[str] = None
        self._assumed_secret_key_id: Optional[str] = None
        self._amazon_session_token: Optional[str] = None

    def _get_headers(self) -> str:
        header_list = list(self._headers.keys())
        header_list.sort()
        header_entries = []
        for header in header_list:
            header_entries.append('{header}:{value}\n'.format(
                header=header,
                value=self._headers.get(header)
            ))
        return ''.join(header_entries)

    def _get_signed_header_names(self) -> str:
        header_list = list(self._headers.keys())
        header_list.sort()
        return ';'.join(header_list)

    def _get_canonical(self, request: _SpApiRequest):
        return '{http_method}\n{uri}\n{query_string}\n{headers}\n{signed_headers}\n{payload}'.format(
            http_method=request.method.upper(),
            uri=request.endpoint,
            query_string=request.get_query_string(),
            headers=self._get_headers(),
            signed_headers=self._get_signed_header_names(),
            payload=_hash_string(request.payload_as_string())
        )

    def _access_token_expired(self) -> bool:
        if self._access_token_expires is None:
            return True
        return self._access_token_expires <= datetime.datetime.utcnow()

    def _create_signing_key(self, request_date: str, service: str) -> bytes:
        key_date = hmac.new(
            key=f'AWS4{self._assumed_secret_key_id}'.encode('utf-8'),
            msg=request_date.encode('utf-8'),
            digestmod=hashlib.sha256
        ).digest()

        key_region = hmac.new(
            key=key_date,
            msg=self.AWS_REGION.encode('utf-8'),
            digestmod=hashlib.sha256
        ).digest()

        key_service = hmac.new(
            key=key_region,
            msg=service.encode('utf-8'),
            digestmod=hashlib.sha256
        ).digest()

        return hmac.new(
            key=key_service,
            msg='aws4_request'.encode('utf-8'),
            digestmod=hashlib.sha256
        ).digest()

    def make_request(self, request: _SpApiRequest) -> SpApiResponse:
        if self._access_token is None or self._access_token_expired():
            self._get_access_token()

        now: datetime.datetime = datetime.datetime.utcnow()
        request_date_time: str = now.strftime('%Y%m%dT%H%M%SZ')
        request_date: str = now.strftime('%Y%m%d')

        assumed_role = self._assume_role()
        credentials: Dict[str, str] = assumed_role.get('Credentials', {})
        self._assumed_access_key_id = credentials.get('AccessKeyId')
        self._assumed_secret_key_id = credentials.get('SecretAccessKey')
        self._amazon_session_token = credentials.get('SessionToken')

        self._headers = {
            'x-amz-access-token': self._access_token,
            'x-amz-date': request_date_time,
            'x-amz-security-token': self._amazon_session_token,
            'user-agent': 'NetXL/2.0',
            'host': 'sellingpartnerapi-eu.amazon.com'
        }

        scope = '{date}/{region}/execute-api/aws4_request'.format(
            date=request_date,
            region='eu-west-1',
        )

        hashed_canonical = _hash_string(self._get_canonical(request))
        string_to_sign = '{algo}\n{request_date}\n{scope}\n{hashed_canonical}'.format(
            algo=self.AWS_ALGORITH,
            request_date=request_date_time,
            scope=scope,
            hashed_canonical=hashed_canonical
        )

        signature = hmac.new(
            key=self._create_signing_key(request_date, 'execute-api'),
            msg=string_to_sign.encode('utf-8'),
            digestmod=hashlib.sha256
        ).hexdigest()

        self._headers['Authorization'] = f'{self.AWS_ALGORITH} Credential={self._assumed_access_key_id}/{scope},SignedHeaders={self._get_signed_header_names()},Signature={signature}'

        import requests
        outcome = requests.get(
            url=f'{self._base_url}{request.endpoint}',
            headers=self._headers,
            params=request.query_string
        )
        if not outcome.ok:
            raise ValueError('Amazon SP-API call failed')

        return request.make_response(outcome.json())

    def _assume_role(self) -> Dict[str, str]:
        import boto3
        import uuid
        client = boto3.client(
            'sts',
            aws_access_key_id=self._aws_credentials.access_key_id,
            aws_secret_access_key=self._aws_credentials.secret_key_id
        )
        assumed_role_object = client.assume_role(
            RoleArn=self._aws_credentials.role_arn,
            RoleSessionName=str(uuid.uuid4())
        )
        return assumed_role_object

    def _sign_request(self, request: _SpApiRequest) -> str:
        pass

    def _get_access_token(self):
        import requests
        access_token_request = requests.post(
            url='https://api.amazon.com/auth/o2/token',
            data={
                'grant_type': 'refresh_token',
                'refresh_token': self._refresh_token,
                'client_id': self._lwa_credentials.client_id,
                'client_secret': self._lwa_credentials.client_secret
            }
        )
        if access_token_request.status_code != 200:
            raise ValueError('Could not obtain access token from Amazon')

        access_token = access_token_request.json()
        self._access_token = access_token.get('access_token', None)
        self._refresh_token = access_token.get('refresh_token', None)

        expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=access_token.get('expires_in', 0))
        self._access_token_expires = expires


class ListOrdersRequest(_SpApiRequest):
    def __init__(self, client, marketplaces: List[str]):
        super().__init__(client=client, method='GET', endpoint='/orders/v0/orders', response_type=ListOrdersResponse)
        self.query_string: Dict[str, str] = {
            'MarketplaceIds': ','.join(marketplaces),
            'CreatedAfter': '2022-11-04T00:00:00Z',
            'OrderStatuses': 'Unshipped'
        }

    def perform(self) -> ListOrdersResponse:
        return self.client.make_request(self)


class Order(object):
    def __init__(self, data: Dict[str, any]):
        self.order_id: str = data.get('AmazonOrderId', None)
        self.status: str = data.get('OrderStatus', None)
        self.purchase_date: datetime.datetime = data.get('PurchaseDate', None)
