using MongoDB.Driver;

namespace Net.AS2.Data.Entity.Context
{
    public interface IAS2DatabaseContext
    {
        void SetConnection(string connectionString);
        string GetConnection();
        IQueryable<T> Table<T>(string collectionName);
    }
    public class AS2MongoDBContext : IAS2DatabaseContext
    {
        private string _connectionString;
        protected IMongoDatabase _database;
        public AS2MongoDBContext(AdminInfo adminInfo)
        {
            if (string.IsNullOrEmpty(_connectionString))
                PrepareMongoDatabase(adminInfo.MainConnectionString);
        }
        public AS2MongoDBContext(string connectionString)
        {
            PrepareMongoDatabase(connectionString);
        }

        private void PrepareMongoDatabase(string connectionString)
        {
            _connectionString = connectionString;
            var mongourl = new MongoUrl(connectionString);
            var databaseName = mongourl.DatabaseName;
            _database = new MongoClient(connectionString).GetDatabase(databaseName);
        }
        public IMongoDatabase Database()
        {
            return _database;
        }
        public string GetConnection()
        {
            return _connectionString;
        }
        public void SetConnection(string connectionString)
        {
            if (string.IsNullOrEmpty(connectionString))
                throw new ArgumentNullException(nameof(connectionString));

            PrepareMongoDatabase(connectionString);
        }

        public bool InstallProcessCreateTable => true;
        public bool InstallProcessCreateIndex => true;

        public IQueryable<T> Table<T>(string collectionName)
        {
            if (string.IsNullOrEmpty(collectionName))
                throw new ArgumentNullException(nameof(collectionName));

            return _database.GetCollection<T>(collectionName).AsQueryable();
        }
    }
}
