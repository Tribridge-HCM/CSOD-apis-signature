# python
import base64
import hashlib
import hmac
from datetime import datetime
# thrid party python
import requests

def make_signature(**dict_inputs):
    """
    :param dict_inputs: a dictionary of strings that has keys
        'url' - this is the absolute URL that always ends in '/' e.g. '/a/b/c/, but we append it if not there.
        'token' - provided by Cornerstone.
        'secret' - provided by Cornerstone. we decode it before using it.
        'date' - if given, we use this. otherwise, we use current UTC time.
        'signature' - this is optional.

    :return: a dictionary with 2 keys. {
        'signature':a base64 encoded HMAC signature,
        'date':the timestamp needed to put into the headers'}
        both are needed to be added to the cornerstone request headers.
    NOTES:
    - url should always be absolute (no domain or https://)
    - current date/time will be used if not provided.
    - IMPORTANT: date should be returned along with the string b/c it needs to be added to headers later.
    - if signature and date are provided, we can validate if correct. that is why we have variable named 'had_date'
    """
    secret=dict_inputs.pop('secret')
    decoded_secret=base64.b64decode(secret)
    # print "decoded_secret",decoded_secret
    had_date=True
    if not dict_inputs.has_key('date'):
        dict_inputs['date']=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%SZ')
        had_date=False
    if not dict_inputs['url'].endswith('/'):
        dict_inputs['url']+='/'
    string_to_sign = "POST\nx-csod-date:%(date)s\nx-csod-session-token:%(token)s\n%(url)s"%dict_inputs
    z=hmac.new(decoded_secret,
               string_to_sign,
               hashlib.sha512)
    our_signature=base64.standard_b64encode(z.digest())
    correct_signature=dict_inputs.pop('signature',None)
    # this next section is just same extra validation in case you want to check against a known good timestamp and signature combination.
    if correct_signature and had_date:
        print "correct_signature",correct_signature
        if our_signature != correct_signature:
            print "they DO NOT match",our_signature
        else: print "they match"
    dict_return={'signature': our_signature,
                 'date': dict_inputs['date']}
    print "dict_return",dict_return
    return dict_return



def test_sig(dict_data):
    """this creates the signature, adds it the headers and then send the call to cornerstone
    """
    print dict_data
    dict_soap_headers={
            'Content-Type':'text/xml',
            'x-csod-date': dict_data['date'],
            'x-csod-session-token': dict_data['token'],
            'x-csod-signature': dict_data['signature']
    }
    print "dict_soap_headers",dict_soap_headers
    full_api_endpoint = dict_data['api_prefix']+dict_data['url']
    response=requests.post(url=full_api_endpoint,
                       data=dict_data.get('post_data','anything here'),
                       headers=dict_soap_headers)
    # we know that it works if we don't see this <status>401</status>
    print response.status_code,response.text
