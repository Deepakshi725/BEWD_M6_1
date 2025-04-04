const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const secretKey = 'deepakshi@123'; // For signing the JWT
const encryptionKey = crypto.randomBytes(32); // 32 bytes key for AES-256
const iv = crypto.randomBytes(16); // Initialization vector


const encrypt = (payload) => {
  // encrypt the payload and return token
    // Step 1: Create JWT token
    const token = jwt.sign(payload, secretKey, { expiresIn: '1h' });

    // Step 2: Encrypt the token using AES
    const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, iv);
    let encrypted = cipher.update(token, 'utf8', 'hex');
    encrypted += cipher.final('hex');
  
    // Return encrypted string along with IV (needed for decryption)
    return iv.toString('hex') + ':' + encrypted;
}

const decrypt = (token) => {
  // return decoded payload
    // Split IV and encrypted data
    const parts = token.split(':');
    const ivBuffer = Buffer.from(parts[0], 'hex');
    const encryptedData = parts[1];
  
    // Decrypt the token
    const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, ivBuffer);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
  
    // Verify JWT and return payload
    return jwt.verify(decrypted, secretKey);
}

module.exports = {
  encrypt,
  decrypt
};
