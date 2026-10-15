RB = ('SELECT id, customer_id, amount, state, version FROM orders ORDER BY id DESC LIMIT 3',
      'SELECT id, destination, LENGTH(headers) AS headers_len, LENGTH(payload) AS payload_len, LEFT(payload,70) AS payload_head, RIGHT(payload,12) AS payload_tail, published FROM message ORDER BY creation_time DESC, id DESC LIMIT 3')
def amount(total_len):  # payload = '{"orderDetails":{"customerId":1,"orderTotal":{"amount":' + X + '}}}' -> 58 + len(X)
    n = total_len - 58
    return '1.' + '0' * (n - 3) + '1'
a1000 = amount(1000); a1001 = amount(1001)
assert len(a1000) == 942 and len(a1001) == 943
# JSON number (not string) so the body carries the exact BigDecimal literal
run('C02-boundary-payload-1000', 'boundary', 'POST', '/orders', '{"customerId":1,"orderTotal":{"amount":%s}}' % a1000, RB)
run('C03-violation-payload-1001', 'violation', 'POST', '/orders', '{"customerId":1,"orderTotal":{"amount":%s}}' % a1001, RB)
run('C04-violation-payload-1500', 'violation', 'POST', '/orders', '{"customerId":1,"orderTotal":{"amount":%s}}' % amount(1500), RB)
run('C05-client-supplied-order-id', 'violation', 'POST', '/orders', {'id': 2, 'orderId': 2, 'customerId': 7, 'orderTotal': {'amount': '5.00'}}, RB)
run('C06-readback-orders', 'read-back', 'GET', '/orders', None, RB)
