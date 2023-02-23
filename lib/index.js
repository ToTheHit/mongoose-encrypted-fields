const { ClientEncryption } = require('mongodb-client-encryption');
const mongoose = require('mongoose');
const { Binary } = require('mongodb');

Binary.prototype.toString = function (type = null) {
    if (!type) {
        return this;
    }

    return this.toString(type);
};
const collectFieldForEncryptionDefault = schema => {
    const fieldsForEncryption = {};
    const buildParentField = (parentField, currentField, isArray = false) => {
        if (!parentField) {
            return currentField;
        }

        if (isArray) {
            return `${parentField}.*.${currentField}`;
        }

        return `${parentField}.${currentField}`;
    };

    const buildFieldForEncryption = (subSchema, parentField = '', isArray = false) => {
        for (const field of Object.keys(subSchema.tree)) {
            if (Array.isArray(subSchema.tree[field].type)) {
                if (subSchema.tree[field].type[0] instanceof mongoose.Schema) {
                    buildFieldForEncryption(
                        subSchema.tree[field].type[0],
                        buildParentField(parentField, field),
                        true
                    );
                } else if (typeof subSchema.tree[field].type[0].type === 'object') {
                    buildFieldForEncryption(
                        { tree: subSchema.tree[field].type[0] },
                        buildParentField(parentField, field),
                        true
                    );
                } else {
                    const fieldType = subSchema.tree[field].type[0].type && subSchema.tree[field].type[0].type.name;

                    if (['String', 'Number', 'Mixed'].includes(fieldType) && subSchema.tree[field].type[0].encrypted) {
                        fieldsForEncryption[`${buildParentField(parentField, field, isArray)}.*`] = true;
                    }
                }
            } else if (subSchema.tree[field].type instanceof mongoose.Schema) {
                buildFieldForEncryption(
                    subSchema.tree[field].type,
                    buildParentField(parentField, field, isArray),
                    false
                );
            } else {
                const fieldType = subSchema.tree[field].type && subSchema.tree[field].type.name;

                if (['String', 'Number'].includes(fieldType) && subSchema.tree[field].encrypted) {
                    fieldsForEncryption[buildParentField(parentField, field, isArray)] = true;
                }
            }
        }
    };

    buildFieldForEncryption(schema);

    return fieldsForEncryption;
};

function EncryptedFieldsPlugin(schema, options = {}) {
    const {
        algorithm = 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic',
        encryptionSecret = null,
        encryptionKey = null,
        keyVaultData = {
            dbName: 'encryption',
            collectionName: '__keyVault'
        },
        collectFieldForEncryption = collectFieldForEncryptionDefault
    } = options;

    let encryptionKeyData = null;

    if (!encryptionKey || !encryptionSecret || !keyVaultData) {
        // TODO: Add error text
        throw new Error('NOT IMPLEMENTED');
    }
    let isPluginReady = false;
    let client;
    let clientEncryption;

    const fieldsForEncryption = collectFieldForEncryption(schema);

    // TODO: call this function for NOT test environment
    const connectClientEcnryption = () => {
        client = mongoose.connection.getClient();

        clientEncryption = new ClientEncryption(client, {
            keyVaultNamespace: `${keyVaultData.dbName}.${keyVaultData.collectionName}`,
            kmsProviders: {
                local: {
                    key: encryptionSecret
                }
            }
        });

        isPluginReady = true;
    };

    const getEncryptionKeyData = async () => {
        if (encryptionKeyData) {
            return encryptionKeyData;
        }

        const keyObjectDb = await client
            .db(keyVaultData.dbName)
            .collection(keyVaultData.collectionName)
            .findOne({ keyAltNames: { $in: [encryptionKey] } });

        if (keyObjectDb) {
            encryptionKeyData = keyObjectDb._id;

            return keyObjectDb._id;
        }

        encryptionKeyData = await clientEncryption.createDataKey('local', {
            keyAltNames: [encryptionKey]
        });

        return encryptionKeyData;
    };

    async function iterateObjectKeys(object, prefix = '', fn = value => value) {
        for (const key of Object.keys(object)) {
            const updatedPrefix = `${prefix}${prefix.length > 0 ? '.' : ''}${Number.isInteger(+key) ? '*' : key}`;

            if (Object(object[key]) === object[key] && !(object[key] instanceof Binary)) {
                const data = object[key] instanceof mongoose.Types.Subdocument ? object[key]._doc : object[key];

                // eslint-disable-next-line no-await-in-loop
                await iterateObjectKeys(
                    data,
                    updatedPrefix,
                    fn
                );
            } else if (fieldsForEncryption[updatedPrefix]) {
                // eslint-disable-next-line no-await-in-loop,no-param-reassign
                object[key] = await fn(object[key]);
            }
        }
    }

    const encryptField = async value => {
        const keyId = encryptionKeyData || await getEncryptionKeyData();

        return clientEncryption.encrypt(value, {
            keyId,
            algorithm
        });
    };
    const decryptField = async value => clientEncryption.decrypt(value);

    const encryptInstance = async instance => {
        const data = instance instanceof mongoose.Document ? instance._doc : instance;

        await iterateObjectKeys(data, '', async value => {
            if (['number', 'string'].includes(typeof value)) {
                return encryptField(value);
            }

            return value;
        });

        return data;
    };
    const decryptInstance = async instance => {
        const data = instance instanceof mongoose.Document ? instance._doc : instance;

        await iterateObjectKeys(data, '', value => {
            if (value instanceof Binary) {
                return decryptField(value);
            }

            return value;
        });

        return data;
    };

    schema.pre('save', async function () {
        // FIXME: hack for tests
        if (!isPluginReady) {
            connectClientEcnryption();
        }

        await encryptInstance(this);
    });

    schema.post('findOne', async function (instance) {
        if (!isPluginReady) {
            connectClientEcnryption();
        }
        await decryptInstance(instance);
    });

    schema.post('find', async function (instances) {
        if (!isPluginReady) {
            connectClientEcnryption();
        }
        const promises = [];

        for (const instance of instances) {
            promises.push(decryptInstance(instance));
        }
        await Promise.all(promises);
    });

    // eslint-disable-next-line no-param-reassign
    schema.statics.encryptField = encryptField;
    // eslint-disable-next-line no-param-reassign
    schema.statics.decryptField = decryptField;

    // eslint-disable-next-line no-param-reassign
    schema.statics.encryptInstance = encryptInstance;
    // eslint-disable-next-line no-param-reassign
    schema.statics.decryptInstance = decryptInstance;
}

module.exports = {
    EncryptedFieldsPlugin
};
