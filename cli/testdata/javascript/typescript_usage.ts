import * as crypto from 'crypto';

function hashData(data: string): string {
    return crypto.createHash('sha256').update(data).digest('hex');
}

function encryptAES(key: Buffer, iv: Buffer, data: Buffer): Buffer {
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    return Buffer.concat([cipher.update(data), cipher.final()]);
}

const algorithm: string = 'sha384';
const configuredHash = crypto.createHash(algorithm);
