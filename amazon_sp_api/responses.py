from typing import Dict, List, Optional, Type

from amazon_sp_api.objects import Order, BuyerInfo, OrderItem, Address


class SpApiResponse(object):
    def __init__(self, data: Dict[str, any]):
        if data.get('payload', None) is None:
            raise ValueError('Missing payload key')


class ListOrdersResponse(SpApiResponse):
    def __init__(self, data: Dict[str, any]):
        super().__init__(data)
        payload = data.get('payload', {})
        self.orders: List[Order] = [Order(data=x) for x in payload.get('Orders', [])]


class GetOrderResponse(SpApiResponse):
    def __init__(self, data: Dict[str, any]):
        super().__init__(data)
        self.order: Order = Order(data=data.get('payload', {}))


class GetOrderBuyerInfoResponse(SpApiResponse):
    def __init__(self, data: Dict[str, any]):
        super().__init__(data)
        self.buyer_info: BuyerInfo = BuyerInfo(data=data.get('payload', {}))


class GetOrderItemsResponse(SpApiResponse):
    def __init__(self, data: Dict[str, any]):
        super().__init__(data)
        payload = data.get('payload', {})
        self.items: List[OrderItem] = [OrderItem(data=x) for x in payload.get('OrderItems', [])]


class GetOrderAddressResponse(SpApiResponse):
    def __init__(self, data: Dict[str, any]):
        super().__init__(data)
        payload = data.get('payload', {})
        self.address: Address = Address(data=payload.get('ShippingAddress', {}))


class ListSupplySourcesResponse(SpApiResponse):
    def __init__(self, data: Dict[str, any]):
        super().__init__(data)


class CreateSupplySourcesResponse(SpApiResponse):
    def __init__(self, data: Dict[str, any]):
        super().__init__(data)


class GetSubscriptionsResponse(SpApiResponse):
    def __init__(self, data: Dict[str, any]):
        super().__init__(data)


class GetDestinationsResponse(SpApiResponse):
    def __init__(self, data: Dict[str, any]):
        super().__init__(data)


class CreateDestinationResponse(SpApiResponse):
    def __init__(self, data: Dict[str, any]):
        super().__init__(data)