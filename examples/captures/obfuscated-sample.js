const _0xstrings = ['GET', '/api/orders', 'x-sign', 'timestamp', 'nonce', 'body'];
function _0xpick(i) {
  return _0xstrings[i];
}
function signRequest(body) {
  const timestamp = Date.now().toString();
  const nonce = Math.random().toString(16).slice(2);
  const canonical = [_0xpick(0), _0xpick(1), timestamp, nonce, body].join('\n');
  return CryptoJS.HmacSHA256(canonical, 'sample-public-demo-key').toString();
}
fetch(_0xpick(1), {
  method: _0xpick(0),
  headers: {
    [_0xpick(2)]: signRequest(''),
    'x-timestamp': Date.now().toString()
  }
});
