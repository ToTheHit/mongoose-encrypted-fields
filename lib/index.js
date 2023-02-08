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

    const client = mongoose.connection.getClient();

    const clientEncryption = new ClientEncryption(client, {
        keyVaultNamespace: `${keyVaultData.dbName}.${keyVaultData.collectionName}`,
        kmsProviders: {
            local: {
                key: encryptionSecret
            }
        }
    });

    const fieldsForEncryption = collectFieldForEncryption(schema);

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

    const encrypt = async value => {
        return clientEncryption.encrypt(value, {
            keyId: encryptionKeyData || await getEncryptionKeyData(),
            algorithm
        });
    };

    const decrypt = async value => clientEncryption.decrypt(value);

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

    schema.pre('save', async function () {
        await iterateObjectKeys(this._doc, '', async value => {
            if (['number', 'string'].includes(typeof value)) {
                return encrypt(value);
            }

            return value;
        });
    });

    schema.post('findOne', async function (result) {
        const data = result instanceof mongoose.Document ? result._doc : result;

        await iterateObjectKeys(data, '', value => {
            if (value instanceof Binary) {
                return decrypt(value);
            }

            return value;
        });
    });

    schema.post('find', async function (result) {
        const promises = [];

        for (const instance of result) {
            const data = instance instanceof mongoose.Document ? instance._doc : instance;

            promises.push(iterateObjectKeys(data, '', value => {
                if (value instanceof Binary) {
                    return decrypt(value);
                }

                return value;
            }));
        }
        await Promise.all(promises);
    });
}

module.exports = EncryptedFieldsPlugin;
