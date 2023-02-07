const { ClientEncryption } = require('mongodb-client-encryption');
const mongoose = require('mongoose');

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

    async function getObjectKeys(object, prefix = '') {
        for (const key of Object.keys(object)) {
            const updatedPrefix = `${prefix}${prefix.length > 0 ? '.' : ''}${Number.isInteger(+key) ? '*' : key}`;

            if (Object(object[key]) === object[key]) {
                const data = object[key] instanceof mongoose.Types.Subdocument ? object[key]._doc : object[key];

                // eslint-disable-next-line no-await-in-loop
                await getObjectKeys(
                    data,
                    updatedPrefix
                );
            } else if (fieldsForEncryption[updatedPrefix]) {
                if (['number', 'string'].includes(typeof object[key])) {
                    // eslint-disable-next-line no-param-reassign,no-await-in-loop
                    object[key] = await encrypt(object[key]);
                }
            }
        }
    }

    schema.pre('save', async function () {
        await getObjectKeys(this._doc);
    });
}

module.exports = EncryptedFieldsPlugin;
