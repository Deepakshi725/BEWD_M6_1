// test.js
const { encrypt, decrypt } = require('./script'); // Make sure path is correct

const payload = { userId: 123, name: 'Deepakshi' };

try {
  const encrypted = encrypt(payload);
  console.log('🔐 Encrypted Token:', encrypted);

  const decrypted = decrypt(encrypted);
  console.log('✅ Decrypted Payload:', decrypted);

  console.log('🎉 Success');
} catch (err) {
  console.error('❌ Error:', err.message);
}
