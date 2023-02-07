const mongoose = require('mongoose');
const EncryptedFieldsPlugin = require('../lib');

mongoose.set('strictQuery', true);

const { Schema } = mongoose;

const main = async () => {
    await mongoose.connect('mongodb://localhost/encryption', {
        autoIndex: false,
        useNewUrlParser: true,
        noDelay: true,
        connectTimeoutMS: 3000,
        keepAlive: true,
        keepAliveInitialDelay: 300000,
        useUnifiedTopology: true
    });

    const TmpSchema = new Schema({
        test: {
            type: Number,
            encrypted: true
        }
    }, { _id: false, id: false });
    const AuthorSchema = new Schema({
        firstName: {
            type: String,
            encrypted: true
        },
        lastName: {
            type: String,
            encrypted: true
        },
        tmp: {
            type: TmpSchema
        }
    }, { _id: false });

    const BlogSchmea = new Schema({
        title: {
            type: String,
            encrypted: true
        },
        body: {
            type: String,
            encrypted: true
        },
        date: {
            type: Number
            // encrypted: true
        },
        author: {
            type: [AuthorSchema]
        },
        trash: {
            // type: [{ type: String, encrypted: true }]
            type: [{ type: Schema.Types.Mixed, encrypted: true }]
        }
    });

    // eslint-disable-next-line max-len
    const SECRET =
        '12343ae4b2d178b3f00441788bcabb7d268c1c87c0139d233cb6e8d3be12866177420f0ea6c071a302d05f0599991a4ae8312673c3b824edf8b53ad5cd4f25111b0f4e1ecef74aee491d245f3dbc671d7e0413b3b3e710dac7d7b3ee9f0ea0c0';

    BlogSchmea.plugin(EncryptedFieldsPlugin, {
        encryptionSecret: Buffer.from(SECRET, 'hex'),
        encryptionKey: 'encryption_key',
        keyVaultNamespace: {
            dbName: 'encryption',
            collectionName: '__keyVault'
        },
        enableAutoEncryptionForFindOperations: true
    });

    const Blog = mongoose.model('blogs', BlogSchmea);

    const blogInstance = new Blog({
        // title: 'Иванов',
        // body: 'иванов',
        // date: new Date(),
        // author: [{
        //     firstName: 'Тестовый',
        //     lastName: 'Тест'
        // }],
        trash: ['какой-то тест']
        // trash: [123]
    });

    // await Blog.findOne({
    //     title: 'Иванов'
    // });
    await blogInstance.save();

    // const blogInstance1 = new Blog({
    //     title: 'Иванов',
    //     body: 'иванов',
    //     date: new Date(),
    //     author: {
    //         firstName: 'Тестовый',
    //         lastName: 'Тест'
    //     }
    // });
    //
    // // await Blog.findOne({
    // //     title: 'Иванов'
    // // });
    // await blogInstance1.save();
};

main();
