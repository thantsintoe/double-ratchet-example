// example.js
const Ratchet = require('./client');

// Helper function to convert buffer to hex string
function toHex(buffer) {
    return buffer.toString('hex');
}

// Initialize Alice and Bob
const alice = new Ratchet(true); // Alice is the initiator
const bob = new Ratchet(false);  // Bob is the responder

// Exchange initial public keys and initialize sessions
alice.initialize(bob.publicKey);
bob.initialize(alice.publicKey);

// Function to simulate message exchange
function exchangeMessages(sender, receiver, ...messages) {
    messages.forEach((message) => {
        console.log(`\n${sender === alice ? 'Alice' : 'Bob'} sends: "${message}"`);
        const packet = sender.encrypt(message);
        console.log(`Encrypted message: ${toHex(packet.ciphertext)}`);
        const receivedMessage = receiver.decrypt(packet);
        console.log(`${receiver === alice ? 'Alice' : 'Bob'} receives: "${receivedMessage}"`);
    });
}

// Exchange messages with multiple messages in one call
exchangeMessages(alice, bob, 'Hello Bob!', 'How are you doing?');
exchangeMessages(bob, alice, 'Hi Alice!', 'I am doing well, thanks!');
exchangeMessages(alice, bob, 'Glad to hear that.', 'See you soon!');

// Display final root keys to show they are synchronized
console.log('\nFinal Root Keys:');
console.log(`Alice's Root Key: ${toHex(alice.rootKey)}`);
console.log(`Bob's Root Key:   ${toHex(bob.rootKey)}`);
