const assertions = require('./test-utils/mongo');
const Blog = require('./test-utils/models/Blog');

const defaultData = {
    title: 'title',
    body: 'body',
    date: Date.now(),
    author: [{
        firstName: 'author firstName',
        lastName: 'author lastName'
    }],
    trash: ['something string']
};

describe('mongoose encrypted fields', () => {
    before(async () => {
        await assertions.connect();
    });

    after(async () => {
        await assertions.disconnect();
    });

    it('Should not affect "new" instance of model', async () => {
        const blogInstance = new Blog(defaultData);

        blogInstance.toJSON().should.have.properties(defaultData);
    });

    it('Should encrypt fields after save', async () => {
        const blogInstance = new Blog(defaultData);

        await blogInstance.save();

        const encryptedData = await Blog.encryptInstance(JSON.parse(JSON.stringify(defaultData)));

        blogInstance.toJSON().should.have.properties(encryptedData);
    });

    it('Should decrypt fields after findOne', async () => {
        const blogInstance = new Blog(defaultData);

        await blogInstance.save();

        const blogInstanceFind = await Blog.findOne({ _id: blogInstance.id });

        blogInstanceFind.toJSON().should.have.properties(defaultData);

        const blogInstanceFindLean = await Blog.findOne({ _id: blogInstance.id }).lean();

        blogInstanceFindLean.should.have.properties(defaultData);
    });
});
