""" Redsys payment processing. """
from __future__ import unicode_literals

import logging
import re
import uuid
import json
import base64
import pyDes
import hmac
import hashlib
import time
from decimal import Decimal
from urlparse import urljoin
from django import forms

import waffle
from django.conf import settings
from django.urls import reverse
from django.utils.functional import cached_property
from django.utils.translation import get_language
from oscar.apps.payment.exceptions import GatewayError

from ecommerce.core.url_utils import get_ecommerce_url
from ecommerce.extensions.payment.processors import BasePaymentProcessor, HandledProcessorResponse
from ecommerce.extensions.payment.utils import middle_truncate

logger = logging.getLogger(__name__)

def compute_signature(salt, payload, key):
    '''
    For Redsys:
        salt = order number (Ds_Order or Ds_Merchant_Order)
        payload = Ds_MerchantParameters
        key = shared secret (aka key) from the Redsys Administration Module
              (Merchant Data Query option in the "See Key" section)
    '''
    try:
      bkey = base64.b64decode(key)
    except TypeError as e:
      logger.error(repr(e) + ". Invalid shared_secret key.") 
    des3 = pyDes.triple_des(bkey, mode=pyDes.CBC, IV=b'\0\0\0\0\0\0\0\0', pad=b'\0', padmode=pyDes.PAD_NORMAL)
    pepper = des3.encrypt(str(salt))
    payload_hash = hmac.new(pepper, payload, hashlib.sha256).digest()
    return base64.b64encode(payload_hash)


def compare_signatures(sig1, sig2):
    alphanumeric_characters = re.compile('[^a-zA-Z0-9]')
    sig1safe = re.sub(alphanumeric_characters, '', sig1)
    sig2safe = re.sub(alphanumeric_characters, '', sig2)
    return sig1safe == sig2safe

class RedsysResponseForm(forms.Form):
    Ds_SignatureVersion = forms.CharField(max_length=256)
    Ds_Signature = forms.CharField(max_length=256)
    Ds_MerchantParameters = forms.CharField(max_length=2048)

class Redsys(BasePaymentProcessor):
    """
    Redsys REST API (2020)

    For reference, see https://desarrolladores.santandertpv.es/conexion-redireccion.html
    """
    NAME = 'redsys'
    DEFAULT_PROFILE_NAME = 'default'
    json_prefix = "DS_MERCHANT_"

    shared_secret_test = "sq7HjrUOBfKmC576ILgskD5srU870gJ7"

    @property
    def receipt_page_url(self):
        logger.info(str(get_ecommerce_url())) 
        return urljoin(get_ecommerce_url(), reverse('redsys:execute'))
        #return get_ecommerce_url(self.configuration.get('urlok', '/redsys/execute/'))

    @property
    def error_page_url(self):
        return get_ecommerce_url(self.configuration.get('urlko', '/checkout/error/'))

    def __init__(self, site):
        """
        Constructs a new instance of the Redsys processor.
        
        Raises:
            KeyError: If a required setting is not configured for this payment processor
        """
        super(Redsys, self).__init__(site)
        
        self.merchant_code = self.configuration.get('merchantcode')
        self.terminal = self.configuration.get('terminal')
        self.shared_secret = self.configuration.get('shared_secret') # key = shared secret (aka key) from the Redsys Administration Module
        self.transactiontype = self.configuration.get('transactiontype','0')
        #PRUEBAS endpoint: https://sis-t.redsys.es:25443/sis/realizarPago
        #REAL endpoint: https://sis.redsys.es/sis/realizarPago
        #LOG: #http://pre-openedx2.ti.uam.es:3721
        self.endpoint = self.configuration.get('endpoint', 'https://sis-t.redsys.es:25443/sis/realizarPago') 

        self.order_number_prefix = self.configuration.get('order_number_prefix','00')
        self.signature_version = self.configuration.get('signature_version','HMAC_SHA256_V1')

    def get_transaction_parameters(self, basket, request=None, use_client_side_checkout=False, **kwargs):
        #alphanumeric_characters = re.compile('[^a-zA-Z0-9]')
        #self.order_number = '%s%s' % (self.order_number_prefix,re.sub(alphanumeric_characters, '', basket.order_number))
        
        self.order_number = basket.order_number
        self.amount = str(int(basket.total_incl_tax * 100)) # price in cents
        
        merchant_data = {
            "DS_MERCHANT_AMOUNT": str(self.amount),
            "DS_MERCHANT_ORDER": str(self.order_number),
            "DS_MERCHANT_MERCHANTCODE": str(self.merchant_code),
            "DS_MERCHANT_CURRENCY": str(self.configuration.get('currency','978')),
            "DS_MERCHANT_TRANSACTIONTYPE": str(self.transactiontype),
            "DS_MERCHANT_TERMINAL": str(self.terminal),
            #"DS_MERCHANT_MERCHANTURL": get_ecommerce_url(),
            "DS_MERCHANT_URLOK": str(self.receipt_page_url),
            "DS_MERCHANT_URLKO": str(self.error_page_url)
        }
        json_data = json.dumps(merchant_data)
        b64_params = base64.b64encode(json_data.encode())

        #REAL:
        #signature = compute_signature(self.order_number, b64_params, self.shared_secret)
        #PRUEBAS:
        signature = compute_signature(self.order_number, b64_params, Redsys.shared_secret_test)

        parameters = {
            'Ds_SignatureVersion': self.signature_version,
            'Ds_MerchantParameters': b64_params.decode(),
            'Ds_Signature': signature.decode(),
        }

        parameters['payment_page_url'] = self.endpoint

        entry = self.record_processor_response(merchant_data, transaction_id=self.order_number, basket=basket)

        return parameters

    def handle_processor_response(self, response, basket):
        """
        Handle a response (i.e., "merchant notification") from redsys.
        """     
        payment = RedsysResponseForm(response)
        self.order_number = basket.order_number
        
        #alphanumeric_characters = re.compile('[^a-zA-Z0-9]')
        #self.order_number = '%s%s' % (self.order_number_prefix,re.sub(alphanumeric_characters, '', basket.order_number))

        if payment.is_valid():
            logger.debug('processing payment gateway response for payment %s' % self.order_number)
            # REAL
            # signature = compute_signature(self.order_number,
            #                               payment.cleaned_data['Ds_MerchantParameters'].encode(),
            #                               self.shared_secret)
            # TEST
            signature = compute_signature(self.order_number,
                                          payment.cleaned_data['Ds_MerchantParameters'].encode(),
                                          Redsys.shared_secret_test)
            logger.debug('received signature: %s' % payment.cleaned_data['Ds_Signature'])
            logger.debug('calculated signature: %s' % signature.decode())
            if not compare_signatures(signature.decode(), payment.cleaned_data['Ds_Signature']):
                logger.debug('signature mismatch - possible attack')
                return HttpResponse()

            binary_merchant_parameters = base64.b64decode(payment.cleaned_data['Ds_MerchantParameters'])
            merchant_parameters = json.loads(binary_merchant_parameters.decode())
            transaction_type = merchant_parameters['Ds_TransactionType']
            response_code = int(merchant_parameters['Ds_Response'])

            if response_code < 100:
                # Authorised transaction for payments
                if transaction_type == '0':
                    #captured_amount = int(merchant_parameters['Ds_Amount']) / 100
                    transaction_id = merchant_parameters['Ds_Order']
                    extra_data = merchant_parameters
                    self.record_processor_response(response, transaction_id=self.order_number, basket=basket)
                    logger.info('payment %s confirmed' % self.order_number)
                    logger.info('basket %s' % basket)
                    logger.info('mparams %s' % merchant_parameters)
                    return HandledProcessorResponse(
                        transaction_id=transaction_id,
                        total=basket.total_incl_tax,
                        currency=basket.currency,
                        # card_number=basket.label,
                        card_number=merchant_parameters['Ds_AuthorisationCode'],
                        card_type=None
                    )
                else:
                    logger.debug('authorised payment response but unrecognised transaction type %s' % transaction_type)

            if response_code == 900:
                # Authorised transaction for refunds and confirmations
                if transaction_type == '3':
                    extra_data = merchant_parameters
                    logger.debug('payment %s automatic refund' % self.order_number)
                else:
                    logger.debug('authorised refund response but unrecognised transaction type %s' % transaction_type)

            if response_code > 100 and response_code != 900:
                # any of a long list of errors/rejections
                extra_data = merchant_parameters
                # perhaps import and raise PaymentError from django-payments
                logger.debug('rejected: %s' % binary_merchant_parameters.decode())


    def issue_credit(self, order_number, basket, reference_number, amount, currency):
        raise NotImplementedError
