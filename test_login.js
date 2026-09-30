const http = require('http');

function post(path, body, token) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const headers = { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) };
    if (token) headers['Authorization'] = 'Bearer ' + token;
    const req = http.request({ host: 'localhost', port: 3000, path, method: 'POST', headers }, res => {
      let b = '';
      res.on('data', c => b += c);
      res.on('end', () => resolve({ status: res.statusCode, body: b }));
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

(async () => {
  // 测试管理员登录
  const admin = await post('/api/admin/login', { password: '小君久久这样子' });
  console.log('Admin login:', admin.status, admin.body.substring(0, 100));

  // 测试验证码发送接口（看看有没有报错）
  const code = await post('/api/send-code', { email: 'test@test.com' });
  console.log('Send code:', code.status, code.body.substring(0, 100));

  // 测试密码登录
  const pwd = await post('/api/login-password', { email: '541009187@qq.com', password: 'wrongpass' });
  console.log('Password login (wrong):', pwd.status, pwd.body.substring(0, 100));
})();
