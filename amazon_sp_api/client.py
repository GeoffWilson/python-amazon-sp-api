import datetime
import hashlib
import json
from typing import Union

from amazon_sp_api.responses import *


def _hash_string(string_to_hash: str) -> str:
    return hashlib.sha256(string_to_hash.encode('utf-8')).hexdigest()


class _SpApiRequest(object):
    def __init__(self, client, method, endpoint, response_type):
        self.client = client
        self.method: str = method
        self.endpoint: str = endpoint
        self.query_string: Dict[str, str] = {}
        self.payload: Dict[str, Union[List[str], str]] = {}
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

    def do_http_request(self, url, headers, query_string):
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


class Client(object):

    UK_MARKETPLACE = 'A1F83G8C2ARO7P'

    def __init__(
            self,
            refresh_token: str,
            lwa_credentials: LoginWithAmazonCredentials,
            grant_type: str = 'refresh_token',
            scope: Optional[str] = None
    ):
        self._refresh_token = refresh_token
        self._lwa_credentials = lwa_credentials
        self._grant_type = grant_type
        self._scope = scope

        self._base_url: str = 'https://sellingpartnerapi-eu.amazon.com'

        self._headers: Dict[str, str] = {}

        # These values are set by the client when required
        self._access_token: Optional[str] = None
        self._access_token_expires: Optional[datetime.datetime] = None
        self._restricted_token: Optional[str] = None

    def _suitable_token(self) -> str:
        if self._restricted_token is not None:
            return self._restricted_token
        return self._access_token

    def _access_token_expired(self) -> bool:
        if self._access_token_expires is None:
            return True
        return self._access_token_expires <= datetime.datetime.utcnow()

    def set_restricted_token(self, restricted_token: str):
        self._restricted_token = restricted_token

    def make_request(self, request: _SpApiRequest) -> SpApiResponse:
        if self._access_token is None or self._access_token_expired():
            self._get_access_token()

        now: datetime.datetime = datetime.datetime.utcnow()
        request_date_time: str = now.strftime('%Y%m%dT%H%M%SZ')

        self._headers = {
            'x-amz-access-token': self._suitable_token(),
            'x-amz-date': request_date_time,
            'user-agent': 'NetXL/2.0',
            'host': 'sellingpartnerapi-eu.amazon.com'
        }

        outcome = request.do_http_request(
            url=f'{self._base_url}{request.endpoint}',
            headers=self._headers,
            query_string=request.query_string
        )

        print(outcome.content)

        if not outcome.ok:
            raise ValueError('Amazon SP-API call failed')

        try:
            json_data = outcome.json()
        except Exception as _:
            json_data = {'payload': {}}

        return request.make_response(json_data)

    def _get_access_token(self):
        import requests
        if self._grant_type == 'refresh_token':
            data = {
                'grant_type': self._grant_type,
                'refresh_token': self._refresh_token,
                'client_id': self._lwa_credentials.client_id,
                'client_secret': self._lwa_credentials.client_secret
            }
        else:
            data = {
                'grant_type': self._grant_type,
                'client_id': self._lwa_credentials.client_id,
                'client_secret': self._lwa_credentials.client_secret,
                'scope': self._scope
            }
        access_token_request = requests.post(
            url='https://api.amazon.com/auth/o2/token',
            data=data
        )

        if access_token_request.status_code != 200:
            raise ValueError('Could not obtain access token from Amazon')

        access_token = access_token_request.json()
        self._access_token = access_token.get('access_token', None)
        self._refresh_token = access_token.get('refresh_token', None)

        expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=access_token.get('expires_in', 0))
        self._access_token_expires = expires


class ListOrdersRequest(_SpApiRequest):
    def __init__(self, client):
        super().__init__(client=client, method='GET', endpoint='/orders/v0/orders', response_type=ListOrdersResponse)

    def perform(self) -> ListOrdersResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.get(
            url=url,
            headers=headers,
            params=query_string
        )
        return outcome


class GetOrderRequest(_SpApiRequest):
    def __init__(self, client, order_id):
        super().__init__(
            client=client,
            method='GET',
            endpoint=f'/orders/v0/orders/{order_id}',
            response_type=GetOrderResponse
        )
        self.query_string: Dict[str, str] = {}

    def perform(self) -> GetOrderResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.get(
            url=url,
            headers=headers,
            params=query_string
        )
        return outcome


class GetOrderBuyerInfoRequest(_SpApiRequest):
    def __init__(self, client, order_id):
        super().__init__(
            client=client,
            method='GET',
            endpoint=f'/orders/v0/orders/{order_id}/buyerInfo',
            response_type=GetOrderBuyerInfoResponse
        )
        self.query_string: Dict[str, str] = {}

    def perform(self) -> GetOrderBuyerInfoResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.get(
            url=url,
            headers=headers,
            params=query_string
        )
        return outcome


class GetOrderItemsRequest(_SpApiRequest):
    def __init__(self, client, order_id):
        super().__init__(
            client=client,
            method='GET',
            endpoint=f'/orders/v0/orders/{order_id}/orderItems',
            response_type=GetOrderItemsResponse
        )
        self.query_string: Dict[str, str] = {}

    def perform(self) -> GetOrderItemsResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.get(
            url=url,
            headers=headers,
            params=query_string
        )
        return outcome


class GetOrderAddressRequest(_SpApiRequest):
    def __init__(self, client, order_id):
        super().__init__(
            client=client,
            method='GET',
            endpoint=f'/orders/v0/orders/{order_id}/address',
            response_type=GetOrderAddressResponse
        )
        self.query_string: Dict[str, str] = {}

    def perform(self) -> GetOrderAddressResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.get(
            url=url,
            headers=headers,
            params=query_string
        )
        return outcome


class ListSupplySourcesRequest(_SpApiRequest):
    def __init__(self, client):
        super().__init__(
            client=client,
            method='GET',
            endpoint='/supplySources/2020-07-01/supplySources',
            response_type=ListSupplySourcesResponse
        )
        self.query_string: Dict[str, str] = {}

    def perform(self) -> ListSupplySourcesResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.get(
            url=url,
            headers=headers,
            params=query_string
        )
        return outcome


class GetSupplySourceRequest(_SpApiRequest):
    def __init__(self, client, supply_source_id):
        super().__init__(
            client=client,
            method='GET',
            endpoint=f'/supplySources/2020-07-01/supplySources/{supply_source_id}',
            response_type=ListSupplySourcesResponse
        )
        self.query_string: Dict[str, str] = {}

    def perform(self) -> ListSupplySourcesResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.get(
            url=url,
            headers=headers,
            params=query_string
        )
        return outcome


class CreateSupplySourcesRequest(_SpApiRequest):
    def __init__(self, client):
        super().__init__(
            client=client,
            method='POST',
            endpoint='/supplySources/2020-07-01/supplySources',
            response_type=CreateSupplySourcesResponse
        )
        self.query_string: Dict[str, str] = {}

    def perform(self) -> CreateSupplySourcesResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.post(
            url=url,
            headers=headers,
            params=query_string,
            data=self.payload_as_string()
        )
        return outcome


class UpdateSupplySourceRequest(_SpApiRequest):
    def __init__(self, client, supply_source_id):
        super().__init__(
            client=client,
            method='PUT',
            endpoint=f'/supplySources/2020-07-01/supplySources/{supply_source_id}',
            response_type=CreateSupplySourcesResponse
        )
        self.query_string: Dict[str, str] = {}

    def perform(self) -> CreateSupplySourcesResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.put(
            url=url,
            headers=headers,
            params=query_string,
            data=self.payload_as_string()
        )
        return outcome


class UpdateSupplySourceStatusRequest(_SpApiRequest):
    def __init__(self, client, supply_source_id):
        super().__init__(
            client=client,
            method='PUT',
            endpoint=f'/supplySources/2020-07-01/supplySources/{supply_source_id}/status',
            response_type=CreateSupplySourcesResponse
        )
        self.query_string: Dict[str, str] = {}

    def perform(self) -> CreateSupplySourcesResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.put(
            url=url,
            headers=headers,
            params=query_string,
            data=self.payload_as_string()
        )
        return outcome


class GetSubscriptionsRequest(_SpApiRequest):
    def __init__(self, client, subscription_type):
        super().__init__(
            client=client,
            method='GET',
            endpoint=f'/notifications/v1/subscriptions/{subscription_type}',
            response_type=GetSubscriptionsResponse
        )
        self.query_string: Dict[str, str] = {}

    def perform(self) -> GetSubscriptionsResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.get(
            url=url,
            headers=headers,
            params=query_string
        )
        return outcome


class GetDestinationsRequest(_SpApiRequest):
    def __init__(self, client):
        super().__init__(
            client=client,
            method='GET',
            endpoint='/notifications/v1/destinations',
            response_type=GetDestinationsResponse
        )
        self.query_string: Dict[str, str] = {}

    def perform(self) -> GetDestinationsResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.get(
            url=url,
            headers=headers,
            params=query_string
        )
        return outcome


class CreateDestinationRequest(_SpApiRequest):
    def __init__(self, client):
        super().__init__(
            client=client,
            method='POST',
            endpoint='/notifications/v1/destinations',
            response_type=CreateDestinationResponse
        )
        self.query_string: Dict[str, str] = {}

    def perform(self) -> CreateDestinationResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.post(
            url=url,
            data=self.payload_as_string(),
            headers=headers,
            params=query_string
        )
        return outcome


class CreateSubscriptionRequest(_SpApiRequest):
    def __init__(self, client, subscription_type):
        super().__init__(
            client=client,
            method='POST',
            endpoint=f'/notifications/v1/subscriptions/{subscription_type}',
            response_type=CreateDestinationResponse
        )
        self.query_string: Dict[str, str] = {}

    def perform(self) -> CreateDestinationResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.post(
            url=url,
            data=self.payload_as_string(),
            headers=headers,
            params=query_string
        )
        return outcome


class UpdateListingClickAndCollectInventory(_SpApiRequest):
    def __init__(self, client, seller_id, sku):
        super().__init__(
            client=client,
            method='PATCH',
            endpoint=f'/listings/2021-08-01/items/{seller_id}/{sku}',
            response_type=CreateDestinationResponse
        )
        self.query_string: Dict[str, str] = {
            'marketplaceIds': 'A1F83G8C2ARO7P'
        }

    def perform(self) -> CreateDestinationResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.patch(
            url=url,
            data=self.payload_as_string(),
            headers=headers,
            params=query_string
        )
        return outcome


class UpdateOrderStatusRequest(_SpApiRequest):
    def __init__(self, client, order_id):
        super().__init__(
            client=client,
            method='POST',
            endpoint=f'/orders/v0/orders/{order_id}/shipment',
            response_type=UpdateOrderStatusResponse
        )
        self.query_string: Dict[str, str] = {}

    def perform(self) -> CreateDestinationResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.post(
            url=url,
            data=self.payload_as_string(),
            headers=headers,
            params=query_string
        )
        return outcome


class GetRestrictedDataToken(_SpApiRequest):
    def __init__(self, client):
        super().__init__(
            client=client,
            method='POST',
            endpoint='/tokens/2021-03-01/restrictedDataToken',
            response_type=RestrictedDataTokenResponse
        )
        self.query_string: Dict[str, str] = {}

    def perform(self) -> RestrictedDataTokenResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.post(
            url=url,
            data=self.payload_as_string(),
            headers=headers,
            params=query_string
        )
        return outcome


class GetEligibleShipmentServices(_SpApiRequest):
    def __init__(self, client):
        super().__init__(
            client=client,
            method='POST',
            endpoint='/mfn/v0/eligibleShippingServices',
            response_type=GetEligibleShipmentServicesResponse
        )
        self.query_string: Dict[str, str] = {}

    def perform(self) -> GetEligibleShipmentServicesResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.post(
            url=url,
            data=self.payload_as_string(),
            headers=headers,
            params=query_string
        )
        return outcome


class CreateShipmentRequest(_SpApiRequest):
    def __init__(self, client):
        super().__init__(
            client=client,
            method='POST',
            endpoint='/mfn/v0/shipments',
            response_type=CreateShipmentResponse
        )
        self.query_string: Dict[str, str] = {}

    def perform(self) -> CreateShipmentResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.post(
            url=url,
            data=self.payload_as_string(),
            headers=headers,
            params=query_string
        )
        return outcome


class RequestReportRequest(_SpApiRequest):
    def __init__(self, client):
        super().__init__(
            client=client,
            method='POST',
            endpoint='/reports/2021-06-30/reports',
            response_type=RequestReportResponse
        )
        self.query_string: Dict[str, str] = {}

    def perform(self) -> RequestReportResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.post(
            url=url,
            data=self.payload_as_string(),
            headers=headers,
            params=query_string
        )
        return outcome


class GetReportRequest(_SpApiRequest):
    def __init__(self, client, report_id):
        super().__init__(
            client=client,
            method='GET',
            endpoint=f'/reports/2021-06-30/reports/{report_id}',
            response_type=GetReportResponse
        )
        self.query_string: Dict[str, str] = {}

    def perform(self) -> GetReportResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.get(
            url=url,
            headers=headers,
            params=query_string
        )
        return outcome


class GetReportDocumentRequest(_SpApiRequest):
    def __init__(self, client, document_id):
        super().__init__(
            client=client,
            method='GET',
            endpoint=f'/reports/2021-06-30/documents/{document_id}',
            response_type=ReportDocumentResponse
        )
        self.query_string: Dict[str, str] = {}

    def perform(self) -> ReportDocumentResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.get(
            url=url,
            headers=headers,
            params=query_string
        )
        return outcome


class GetReportsRequest(_SpApiRequest):
    def __init__(self, client):
        super().__init__(
            client=client,
            method='GET',
            endpoint='/reports/2021-06-30/reports',
            response_type=GetReportsResponse
        )
        self.query_string: Dict[str, str] = {}

    def perform(self) -> GetReportsResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.get(
            url=url,
            data=self.payload_as_string(),
            headers=headers,
            params=query_string
        )
        print(outcome.content)
        return outcome


class ConfirmShipmentRequest(_SpApiRequest):
    def __init__(self, client, order_id):
        super().__init__(
            client=client,
            method='POST',
            endpoint=f'/orders/v0/orders/{order_id}/shipmentConfirmation',
            response_type=ConfirmShipmentResponse
        )
        self.query_string: Dict[str, str] = {}

    def perform(self) -> ConfirmShipmentResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.post(
            url=url,
            data=self.payload_as_string(),
            headers=headers,
            params=query_string
        )
        return outcome


class CreateInboundShipmentPlanRequest(_SpApiRequest):
    def __init__(self, client):
        super().__init__(
            client=client,
            method='POST',
            endpoint='/inbound/fba/2024-03-20/inboundPlans',
            response_type=CreateInboundShipmentPlanResponse
        )
        self.query_string: Dict[str, str] = {}

    def perform(self) -> CreateInboundShipmentPlanResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.post(
            url=url,
            data=self.payload_as_string(),
            headers=headers,
            params=query_string
        )
        return outcome


class GetListingItemRequest(_SpApiRequest):
    def __init__(self, client, seller_id, sku):
        super().__init__(
            client=client,
            method='GET',
            endpoint=f'/listings/2021-08-01/items/{seller_id}/{sku}',
            response_type=GetListingItemResponse
        )
        self.query_string: Dict[str, str] = {
            'marketplaceIds': 'A1F83G8C2ARO7P'
        }

    def perform(self) -> GetListingItemResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.get(
            url=url,
            data=self.payload_as_string(),
            headers=headers,
            params=query_string
        )
        return outcome


class CreateInboundShipmentRequest(_SpApiRequest):
    def __init__(self, client, shipment_id):
        super().__init__(
            client=client,
            method='POST',
            endpoint=f'/fba/inbound/v0/shipments/{shipment_id}',
            response_type=CreateInboundShipmentResponse
        )
        self.query_string: Dict[str, str] = {}

    def perform(self) -> CreateInboundShipmentResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.post(
            url=url,
            data=self.payload_as_string(),
            headers=headers,
            params=query_string
        )
        return outcome


class PatchListingRequest(_SpApiRequest):
    def __init__(self, client, seller_id, product_sku):
        super().__init__(
            client=client,
            method='PATCH',
            endpoint=f'/listings/2021-08-01/items/{seller_id}/{product_sku}',
            response_type=PatchListingResponse
        )
        self.query_string: Dict[str, str] = {}

    def perform(self) -> PatchListingResponse:
        return self.client.make_request(self)

    def do_http_request(self, url, headers, query_string):
        import requests
        outcome = requests.patch(
            url=url,
            data=self.payload_as_string(),
            headers=headers,
            params=query_string
        )
        return outcome
