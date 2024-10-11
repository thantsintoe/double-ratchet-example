// client.js
const crypto = require('crypto');

class Ratchet {
    constructor(isInitiator) {
        // Initialize own DH key pair using X25519
        const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
        this.publicKey = publicKey;
        this.privateKey = privateKey;

        // Root key will be derived during initialization
        this.rootKey = null;

        // Initialize chain keys
        this.sendChainKey = null;
        this.recvChainKey = null;
        this.remotePublicKey = null;

        // Role flag to differentiate initiator and responder
        this.isInitiator = isInitiator;

        // Flag to indicate if we need to generate a new DH key pair
        this.needToRatchet = false;

        // Flag to indicate if this is the first message
        this.isFirstMessage = true;
    }

    // HKDF function
    hkdf(salt, ikm, info, length) {
        const prk = crypto.createHmac('sha256', salt).update(ikm).digest();
        let previousT = Buffer.alloc(0);
        let okm = Buffer.alloc(0);
        const infoBuffer = Buffer.from(info, 'utf8');
        for (let i = 0; okm.length < length; i++) {
            const hmac = crypto.createHmac('sha256', prk);
            hmac.update(Buffer.concat([previousT, infoBuffer, Buffer.from([i + 1])]));
            previousT = hmac.digest();
            okm = Buffer.concat([okm, previousT]);
        }
        return okm.slice(0, length);
    }

    // Root key derivation function
    kdfRoot(rootKey, dhOutput) {
        const salt = rootKey || Buffer.alloc(32, 0);
        const ikm = dhOutput;
        const okm = this.hkdf(salt, ikm, 'DoubleRatchetRoot', 64); // 32 bytes for root key, 32 bytes for chain key
        const newRootKey = okm.slice(0, 32);
        const newChainKey = okm.slice(32, 64);
        console.log(`Running kdfRoot: rootKey: ${rootKey ? rootKey.toString('hex') : 'null'}, dhOutput: ${dhOutput.toString('hex')} --> NEW ROOOT ${newRootKey.toString('hex')}, NEW CHAIN ${newChainKey.toString('hex')}`);
        return { newRootKey, newChainKey };
    }

    // Chain key derivation function
    kdfChainKey(chainKey) {
        const hmac = crypto.createHmac('sha256', chainKey);
        hmac.update('ChainKey');
        const result = hmac.digest();
        console.log(`Running kdfChainKey: chainKey: ${chainKey.toString('hex')} --> ${result.toString('hex')}`);
        return result
    }

    // Message key derivation function
    kdfMessageKey(chainKey) {
        const hmac = crypto.createHmac('sha256', chainKey);
        hmac.update('MessageKey');
        const result = hmac.digest();
        console.log(`Running kdfMessageKey: chainKey: ${chainKey.toString('hex')} --> ${result.toString('hex')}`);
        return result;
    }

    // Initialize session with the remote public key
    initialize(remotePublicKey) {
        this.remotePublicKey = remotePublicKey;

        // Compute shared secret using initial DH key pair
        const sharedSecret = crypto.diffieHellman({
            privateKey: this.privateKey,
            publicKey: this.remotePublicKey,
        });

        // Derive initial root key and chain key
        const { newRootKey, newChainKey } = this.kdfRoot(null, sharedSecret);
        this.rootKey = newRootKey;

        if (this.isInitiator) {
            // Initiator performs a DH ratchet before sending the first message
            this.sendChainKey = newChainKey;
            this.needToRatchet = true;
        } else {
            // Responder sets the receive chain key
            this.recvChainKey = newChainKey;
        }
    }

    // Encrypt a message
    encrypt(plaintext) {
        // Check if we need to perform a DH ratchet
        if (this.needToRatchet || (this.isFirstMessage && this.isInitiator)) {
            console.log('=============== RATCHET ===============');
            // Generate a new DH key pair
            const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
            this.publicKey = publicKey;
            this.privateKey = privateKey;

            // Compute shared secret with the receiver's last known public key
            const sharedSecret = crypto.diffieHellman({
                privateKey: this.privateKey,
                publicKey: this.remotePublicKey,
            });

            // Update root key and send chain key
            const { newRootKey, newChainKey } = this.kdfRoot(this.rootKey, sharedSecret);
            this.rootKey = newRootKey;
            this.sendChainKey = newChainKey;

            // Reset the flag
            this.needToRatchet = false;
            this.isFirstMessage = false;
        } else {
            // Update send chain key for each message
            this.sendChainKey = this.kdfChainKey(this.sendChainKey);
        }

        // Derive message key
        const messageKey = this.kdfMessageKey(this.sendChainKey);

        // Serialize public key for transmission (always include it)
        const dhPublicKey = this.publicKey.export({ type: 'spki', format: 'der' });

        // Encrypt the plaintext
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', messageKey, iv);
        const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
        const authTag = cipher.getAuthTag();

        return {
            dhPublicKey,
            iv,
            authTag,
            ciphertext,
        };
    }

    // Decrypt a message
    decrypt(packet) {
        const { dhPublicKey, iv, authTag, ciphertext } = packet;

        // Deserialize received public key
        const remotePublicKey = crypto.createPublicKey({
            key: dhPublicKey,
            format: 'der',
            type: 'spki',
        });

        // Check if the received DH public key is different
        const receivedDHPublicKeyBytes = remotePublicKey.export({ type: 'spki', format: 'der' });
        const knownDHPublicKeyBytes = this.remotePublicKey
            ? this.remotePublicKey.export({ type: 'spki', format: 'der' })
            : null;

        if (
            !knownDHPublicKeyBytes ||
            !receivedDHPublicKeyBytes.equals(knownDHPublicKeyBytes)
        ) {
            // Perform DH ratchet
            const sharedSecret = crypto.diffieHellman({
                privateKey: this.privateKey,
                publicKey: remotePublicKey,
            });

            // Update root key and receive chain key
            const { newRootKey, newChainKey } = this.kdfRoot(this.rootKey, sharedSecret);
            this.rootKey = newRootKey;
            this.recvChainKey = newChainKey;

            // Update remote public key for future DH computations
            this.remotePublicKey = remotePublicKey;

            // We need to generate a new DH key pair before sending the next message
            this.needToRatchet = true;
        } else {
            // Update receive chain key for each message
            this.recvChainKey = this.kdfChainKey(this.recvChainKey);
        }

        // Derive message key
        const messageKey = this.kdfMessageKey(this.recvChainKey);

        // Decrypt the ciphertext
        const decipher = crypto.createDecipheriv('aes-256-gcm', messageKey, iv);
        decipher.setAuthTag(authTag);
        const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

        return plaintext.toString('utf8');
    }
}

module.exports = Ratchet;
