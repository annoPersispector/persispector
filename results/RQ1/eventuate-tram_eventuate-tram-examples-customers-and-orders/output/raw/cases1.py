RB = ('SELECT id, customer_id, amount, state, version FROM orders ORDER BY id DESC LIMIT 3',
      'SELECT id, destination, LENGTH(headers) AS headers_len, headers, LENGTH(payload) AS payload_len, LEFT(payload,200) AS payload_head, published, creation_time FROM message ORDER BY creation_time DESC LIMIT 3')
run('C01-control-create-order', 'control', 'POST', '/orders', {'customerId': 1, 'orderTotal': {'amount': '12.34'}}, RB)
