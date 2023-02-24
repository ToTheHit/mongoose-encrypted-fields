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

describe('test encrypt and decrypt for fields in body', () => {
    before(async () => {
        await assertions.connect();
    });

    after(async () => {
        await assertions.disconnect();
    });

    describe('create', async () => {
        it('Should not affect "new" instance of model', async () => {
            const blogInstance = new Blog(defaultData);

            blogInstance.toJSON().should.have.properties(defaultData);
        });

        it('Should encrypt fields for create', async () => {
            const blogInstance = await Blog.create(defaultData);

            const encryptedData = await Blog.encryptInstance(JSON.parse(JSON.stringify(defaultData)));

            blogInstance.toJSON().should.have.properties(encryptedData);
        });
    });

    describe('update', async () => {
        it('Should encrypt fields for save', async () => {
            const blogInstance = new Blog(defaultData);

            await blogInstance.save();

            const encryptedData = await Blog.encryptInstance(JSON.parse(JSON.stringify(defaultData)));

            blogInstance.toJSON().should.have.properties(encryptedData);
        });

        it('Should encrypt fields for updateOne', async () => {
            const secondTitle = 'title #2';
            const blogInstance = new Blog(defaultData);

            await blogInstance.save();

            await Blog.updateOne({
                _id: blogInstance._id
            }, {
                $set: {
                    title: secondTitle
                }
            });

            const blogInstanceFind = await Blog.findOne(
                { _id: blogInstance.id },
                {},
                { skipDecrypt: true }
            ).lean();
            const encryptedSecondTitle = await Blog.encryptField(secondTitle);

            blogInstanceFind.should.have.properties({
                title: encryptedSecondTitle
            });
        });

        it('Should encrypt fields for updateMany', async () => {
            const secondTitle = 'title #3';
            const blogInstance = new Blog(defaultData);
            const blogInstance2 = new Blog({ ...defaultData, title: 'title: #2' });

            await blogInstance.save();
            await blogInstance2.save();

            await Blog.updateMany(
                { _id: { $in: [blogInstance._id, blogInstance2._id] } },
                {
                    $set: {
                        title: secondTitle
                    }
                }
            );

            const blogInstanceFind = await Blog.find(
                { _id: { $in: [blogInstance._id, blogInstance2._id] } },
                {},
                { skipDecrypt: true }
            ).lean();
            const encryptedSecondTitle = await Blog.encryptField(secondTitle);

            blogInstanceFind[0].should.have.properties({
                title: encryptedSecondTitle
            });
            blogInstanceFind[1].should.have.properties({
                title: encryptedSecondTitle
            });
        });

        it('Should encrypt fields for update', async () => {
            const secondTitle = 'title #3';
            const blogInstance = new Blog(defaultData);
            const blogInstance2 = new Blog({ ...defaultData, title: 'title: #2' });

            await blogInstance.save();
            await blogInstance2.save();

            await Blog.update(
                { _id: { $in: [blogInstance._id, blogInstance2._id] } },
                {
                    $set: {
                        title: secondTitle
                    }
                }
            );

            const blogInstanceFind = await Blog.find(
                { _id: { $in: [blogInstance._id, blogInstance2._id] } },
                {},
                { skipDecrypt: true }
            ).lean();
            const encryptedSecondTitle = await Blog.encryptField(secondTitle);

            blogInstanceFind[0].should.have.properties({
                title: encryptedSecondTitle
            });
            blogInstanceFind[1].should.have.properties({
                title: encryptedSecondTitle
            });
        });
    });

    describe('find', async () => {
        it('Should decrypt fields after findOne', async () => {
            const blogInstance = new Blog(defaultData);

            await blogInstance.save();

            const blogInstanceFind = await Blog.findOne({ _id: blogInstance.id });

            blogInstanceFind.toJSON().should.have.properties(defaultData);

            const blogInstanceFindLean = await Blog.findOne({ _id: blogInstance.id }).lean();

            blogInstanceFindLean.should.have.properties(defaultData);
        });

        it('Should decrypt fields after find', async () => {
            const blogInstance = new Blog(defaultData);

            await blogInstance.save();

            const blogInstanceFind = await Blog.find({ _id: blogInstance.id });

            blogInstanceFind[0].toJSON().should.have.properties(defaultData);

            const blogInstanceFindLean = await Blog.find({ _id: blogInstance.id }).lean();

            blogInstanceFindLean[0].should.have.properties(defaultData);
        });

        it('Should decrypt fields after findById', async () => {
            const blogInstance = new Blog(defaultData);

            await blogInstance.save();

            const blogInstanceFind = await Blog.findById({ _id: blogInstance.id });

            blogInstanceFind.toJSON().should.have.properties(defaultData);

            const blogInstanceFindLean = await Blog.findById({ _id: blogInstance.id }).lean();

            blogInstanceFindLean.should.have.properties(defaultData);
        });

        it('Should encrypt and decrypt fields for findOneAndUpdate', async () => {
            const secondTitle = 'title #2';
            const blogInstance = new Blog(defaultData);

            await blogInstance.save();

            const updatedBlogInstance = await Blog.findOneAndUpdate(
                {
                    _id: blogInstance._id
                },
                {
                    $set: { title: secondTitle }
                },
                { new: true, skipDecrypt: true }
            );

            const encryptedSecondTitle = await Blog.encryptField(secondTitle);

            updatedBlogInstance.should.have.properties({
                title: encryptedSecondTitle
            });
        });

        it('Should encrypt and decrypt fields for findByIdAndUpdate', async () => {
            const secondTitle = 'title #5';
            const blogInstance = new Blog(defaultData);

            await blogInstance.save();

            const updatedBlogInstance = await Blog.findByIdAndUpdate(
                blogInstance._id,
                {
                    $set: {
                        title: secondTitle
                    }
                },
                { new: true, skipDecrypt: true }
            );

            const encryptedSecondTitle = await Blog.encryptField(secondTitle);

            updatedBlogInstance.should.have.properties({
                title: encryptedSecondTitle
            });
        });
    });
});
