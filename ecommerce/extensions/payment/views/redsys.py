""" Views for interacting with the payment processor. """
from __future__ import unicode_literals

import logging
import os
import json
import base64

from django.core.exceptions import MultipleObjectsReturned
from django.core.management import call_command
from django.db import transaction
from django.http import Http404, HttpResponse, HttpResponseBadRequest
from django.shortcuts import redirect
from django.utils.decorators import method_decorator
from django.views.generic import View
from oscar.apps.partner import strategy
from oscar.apps.payment.exceptions import PaymentError
from oscar.core.loading import get_class, get_model

from ecommerce.extensions.basket.utils import basket_add_organization_attribute
from ecommerce.extensions.checkout.mixins import EdxOrderPlacementMixin
from ecommerce.extensions.checkout.utils import get_receipt_page_url
from ecommerce.extensions.payment.processors.redsys import Redsys


logger = logging.getLogger(__name__)

Applicator = get_class('offer.applicator', 'Applicator')
Basket = get_model('basket', 'Basket')
BillingAddress = get_model('order', 'BillingAddress')
Country = get_model('address', 'Country')
NoShippingRequired = get_class('shipping.methods', 'NoShippingRequired')
OrderNumberGenerator = get_class('order.utils', 'OrderNumberGenerator')
OrderTotalCalculator = get_class('checkout.calculators', 'OrderTotalCalculator')
PaymentProcessorResponse = get_model('payment', 'PaymentProcessorResponse')


class RedsysPaymentExecutionView(EdxOrderPlacementMixin, View):
    """Execute an approved Redsys payment and place an order for paid products as appropriate."""

    @property
    def payment_processor(self):
        return Redsys(self.request.site)

    # Disable atomicity for the view. Otherwise, we'd be unable to commit to the database
    # until the request had concluded; Django will refuse to commit when an atomic() block
    # is active, since that would break atomicity. Without an order present in the database
    # at the time fulfillment is attempted, asynchronous order fulfillment tasks will fail.
    @method_decorator(transaction.non_atomic_requests)
    def dispatch(self, request, *args, **kwargs):
        return super(RedsysPaymentExecutionView, self).dispatch(request, *args, **kwargs)

    def _get_basket(self, payment_id):
        """
        Retrieve a basket using a payment ID.

        Arguments:
            payment_id: payment_id received from PayPal.

        Returns:
            It will return related basket or log exception and return None if
            duplicate payment_id received or any other exception occurred.

        """
        if not payment_id:
            return None
        try:
            basket = PaymentProcessorResponse.objects.get(
                processor_name=self.payment_processor.NAME,
                transaction_id=payment_id
            ).basket
            basket.strategy = strategy.Default()
            Applicator().apply(basket, basket.owner, self.request)

            basket_add_organization_attribute(basket, self.request.GET)
            return basket
        except MultipleObjectsReturned:
            logger.warning(u"Duplicate payment ID [%s] received from Redsys.", payment_id)
            return None
        except Exception:  # pylint: disable=broad-except
            logger.exception(u"Unexpected error during basket retrieval while executing Redsys payment.")
            return None

    def get(self, request):
        binary_merchant_parameters = base64.b64decode(request.GET.get('Ds_MerchantParameters'))
        merchant_parameters = json.loads(binary_merchant_parameters.decode())
        payment_id = merchant_parameters["Ds_Order"]

        basket = self._get_basket(payment_id = payment_id)

        if not basket:
            logger.exception("No basket with id [%d]", payment_id)
            return redirect(self.payment_processor.error_page_url)

        receipt_url = get_receipt_page_url(
            order_number=basket.order_number,
            site_configuration=basket.site.siteconfiguration
        )

        """Handle an incoming user returned to us by Redsys after approving payment."""
        redsys_response = request.GET.dict()
        try:
            with transaction.atomic():
                try:
                    payment_id = self.handle_payment(redsys_response, basket)
                except PaymentError:
                    return redirect(self.payment_processor.error_page_url)
        except:  # pylint: disable=bare-except
            logger.exception('Attempts to handle payment for basket [%d] failed.', basket.id)
            return redirect(receipt_url)

        self.call_handle_order_placement(basket, request)

        return redirect(receipt_url)

    def call_handle_order_placement(self, basket, request):
        try:
            shipping_method = NoShippingRequired()
            shipping_charge = shipping_method.calculate(basket)
            order_total = OrderTotalCalculator().calculate(basket, shipping_charge)

            user = basket.owner
            # Given a basket, order number generation is idempotent. Although we've already
            # generated this order number once before, it's faster to generate it again
            # than to retrieve an invoice number from PayPal.
            order_number = basket.order_number

            order = self.handle_order_placement(
                order_number=order_number,
                user=user,
                basket=basket,
                shipping_address=None,
                shipping_method=shipping_method,
                shipping_charge=shipping_charge,
                billing_address=None,
                order_total=order_total,
                request=request
            )
            self.handle_post_order(order)

        except Exception:  # pylint: disable=broad-except
            self.log_order_placement_exception(basket.order_number, basket.id)


# class PaypalProfileAdminView(View):
#     ACTIONS = ('list', 'create', 'show', 'update', 'delete', 'enable', 'disable')

#     def dispatch(self, request, *args, **kwargs):
#         if not request.user.is_superuser:
#             raise Http404

#         return super(PaypalProfileAdminView, self).dispatch(request, *args, **kwargs)

#     def get(self, request, *_args, **_kwargs):

#         # Capture all output and logging
#         out = StringIO()
#         err = StringIO()
#         log = StringIO()

#         log_handler = logging.StreamHandler(log)
#         formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
#         log_handler.setFormatter(formatter)
#         logger.addHandler(log_handler)

#         action = request.GET.get('action')
#         if action not in self.ACTIONS:
#             return HttpResponseBadRequest("Invalid action.")
#         profile_id = request.GET.get('id', '')
#         json_str = request.GET.get('json', '')

#         command_params = [action]
#         if action in ('show', 'update', 'delete', 'enable', 'disable'):
#             command_params.append(profile_id.strip())
#         if action in ('create', 'update'):
#             command_params.append(json_str.strip())

#         logger.info("user %s is managing paypal profiles: %s", request.user.username, command_params)

#         success = False
#         try:
#             call_command('paypal_profile', *command_params,
#                          settings=os.environ['DJANGO_SETTINGS_MODULE'], stdout=out, stderr=err)
#             success = True
#         except:  # pylint: disable=bare-except
#             # we still want to present the output whether or not the command succeeded.
#             pass

#         # Format the output for display
#         output = u'STDOUT\n{out}\n\nSTDERR\n{err}\n\nLOG\n{log}'.format(out=out.getvalue(), err=err.getvalue(),
#                                                                         log=log.getvalue())

#         # Remove the log capture handler
#         logger.removeHandler(log_handler)

#         return HttpResponse(output, content_type='text/plain', status=200 if success else 500)
