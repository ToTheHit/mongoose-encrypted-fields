const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');

let mongoServer;

module.exports = {
    connect: async () => {
        mongoServer = await MongoMemoryServer.create({
            instance: {
                storageEngine: 'wiredTiger'
            }
        });
        const mongoUri = mongoServer.getUri();

        mongoose.set('strictQuery', true);

        await mongoose.connect(`${mongoUri}test`, {
            autoIndex: false,
            useNewUrlParser: true,
            noDelay: true,
            connectTimeoutMS: 3000,
            keepAlive: true,
            keepAliveInitialDelay: 300000,
            useUnifiedTopology: true
        });
    },
    disconnect: async () => {
        await mongoose.disconnect();
        await mongoServer.stop();
    }
};
