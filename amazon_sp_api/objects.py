from typing import Dict, List, Optional


class Order(object):
    def __init__(self, data: Dict[str, any]):
        self.order_id: str = data.get('AmazonOrderId', None)
        self.status: str = data.get('OrderStatus', None)
        self.purchase_date: str = data.get('PurchaseDate', None)
        self.is_click_and_collect: bool = data.get('IsISPU', False)
        self.is_premium_shipping: bool = data.get('IsPremiumOrder', False)
        self.is_prime: bool = data.get('IsPrime', False)
        self.fulfillment_channel: bool = data.get('FulfillmentChannel', None)
        self.is_business_order: bool = data.get('IsBusinessOrder', False)
        self.deliver_by: str = data.get('LatestDeliveryDate', None)
        self.last_update_date: str = data.get('LastUpdateDate', None)
        self.order_total: Money = Money(data.get('OrderTotal', {}))
        self.shipment_service_level_category: str = data.get('ShipmentServiceLevelCategory', None)
        self.payment_method_details: List[str] = data.get('PaymentMethodDetails', [])
        self.sales_channel: str = data.get('SalesChannel', None)
        self.must_ship_by: str = data.get('LatestShipDate', None)
        self.must_deliver_by: str = data.get('LatestDeliveryDate', None)

        self.items: List[OrderItem] = []
        self.buyer_info: Optional[BuyerInfo] = BuyerInfo(data.get('BuyerInfo', {}))
        self.delivery_address: Optional[Address] = Address(data.get('ShippingAddress', {}))
        self.automated_shipping_settings: Optional[AutomatedShippingSettings] = (
            AutomatedShippingSettings(data.get('AutomatedShippingSettings', {}))
        )

    def is_fba(self):
        return self.fulfillment_channel == 'AFN'


class Address(object):
    def __init__(self, data: Dict[str, any]):
        self.name: str = data.get('Name', None)
        self.address_one: str = data.get('AddressLine1', None)
        self.address_two: str = data.get('AddressLine2', None)
        self.address_three: str = data.get('AddressLine3', None)
        self.city: str = data.get('City', None)
        self.county: str = data.get('County', None)
        self.district: str = data.get('District', None)
        self.state_or_region: str = data.get('StateOrRegion', None)
        self.municipality: str = data.get('Municipality', None)
        self.zip: str = data.get('PostalCode', None)
        self.country_code: str = data.get('CountryCode', None)
        self.phone: str = data.get('Phone', None)
        self.address_type: str = data.get('AddressType', None)


class Money(object):
    def __init__(self, data: Dict[str, any]):
        self.currency: str = data.get('CurrencyCode', None)
        self.amount: str = data.get('Amount', None)


class OrderItem(object):
    def __init__(self, data: Dict[str, any]):
        self.asin: str = data.get('ASIN', None)
        self.our_sku: str = data.get('SellerSKU', None)
        self.order_item_id: str = data.get('OrderItemId', None)
        self.title: str = data.get('Title', None)
        self.quantity_ordered: int = data.get('QuantityOrdered', None)
        self.quantity_shipped: int = data.get('QuantityShipped', None)
        self.item_price: Money = Money(data.get('ItemPrice', {}))
        self.item_tax: Money = Money(data.get('ItemTax', {}))
        self.condition_id: str = data.get('ConditionId', None)

        self.shipping_price: Money = Money(data.get('ShippingPrice', {}))
        if self.shipping_price.amount is None:
            self.shipping_price = None

        self.shipping_tax: Money = Money(data.get('ShippingTax', {}))
        if self.shipping_tax.amount is None:
            self.shipping_tax = None

        self.shipping_discount: Money = Money(data.get('ShippingDiscount', {}))
        if self.shipping_discount.amount is None:
            self.shipping_discount = None

        self.shipping_discount_tax: Money = Money(data.get('ShippingDiscountTax', {}))
        if self.shipping_discount_tax.amount is None:
            self.shipping_discount_tax = None


class BuyerInfo(object):
    def __init__(self, data: Dict[str, any]):
        self.email_address = data.get('BuyerEmail', None)
        self.name = data.get('BuyerName', None)
        self.country = data.get('BuyerCountry', None)
        self.tax_info = data.get('BuyerTaxInfo', None)
        self.purchase_order_number = data.get('PurchaseOrderNumber', None)


class SupplySource(object):
    def __init__(self, data: Dict[str, any]):
        self.code = data.get('supplySourceCode', None)
        self.alias = data.get('alias', None)
        self.address = SupplySourceAddress(data=data.get('address', {}))


class SupplySourceAddress(object):
    def __init__(self, data: Dict[str, any]):
        self.name = data.get('name', None)
        self.addressLineOne = data.get('addressLine1', None)
        self.addressLineTwo = data.get('addressLine2', None)
        self.addressLineThree = data.get('addressLine3', None)
        self.city = data.get('city', None)
        self.county = data.get('count', None)
        self.district = data.get('district', None)
        self.state = data.get('stateOrRegion', None)
        self.postalCode = data.get('postalCode', None)
        self.countryCode = data.get('countryCode', None)
        self.phone = data.get('phone', None)


class AutomatedShippingSettings(object):
    def __init__(self, data: Dict[str, any]):
        self.carrier: Optional[str] = data.get('AutomatedCarrier', None)
        self.has_automation: bool = data.get('HasAutomatedShippingSettings', False)
        self.method: Optional[str] = data.get('AutomatedShipMethod', None)


class InboundShipmentItem(object):
    def __init__(self, data: Dict[str, any]):
        self.fulfillment_sku: Optional[str] = data.get('FulfillmentNetworkSKU', None)
        self.quantity: Optional[int] = data.get('Quantity', None)
        self.sku: Optional[str] = data.get('SellerSKU', None)


class InboundShipmentPlan(object):
    def __init__(self, data: Dict[str, any]):
        self.destination: Optional[str] = data.get('DestinationFulfillmentCenterId', None)
        self.label_type: Optional[str] = data.get('LabelPrepType', None)
        self.shipment_id: Optional[str] = data.get('ShipmentId', None)
        self.items: List[InboundShipmentItem] = [
            InboundShipmentItem(item) for item in data.get('Items', [])
        ]