# How to use
1. Set a your `encryptionSecret`. It should be only 96 bytes long
2. Connect plugin to your schema.
3. Mark fields by `encrypted: true` in schema

```JavaScript
const AuthorSchema = new Schema({
    firstName: {
        type: String,
        encrypted: true
    },
    lastName: {
        type: String,
        encrypted: true
    }
}, { _id: false });

const BlogSchema = new Schema({
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
    },
    author: {
        type: [AuthorSchema]
    }
});

const SECRET = ''; // 96 bytes
BlogSchema.plugin(EncryptedFieldsPlugin, {
    encryptionSecret: Buffer.from(SECRET, 'hex'),
    encryptionKey: 'encryption_key',
    keyVaultNamespace: {
        dbName: 'encryption',
        collectionName: '__keyVault'
    }
});
```

### Note
This plugin doesn't support string array encryption.
For temporary solution, you can use type `Mixed` instead of `String`.  

```JavaScript
{
    // type: [{ type: String, encrypted: true }]
    type: [{ type: Schema.Types.Mixed, encrypted: true }]
}
```
