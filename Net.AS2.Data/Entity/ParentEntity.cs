using MongoDB.Bson;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Net.AS2.Data.Entity
{
    [AttributeUsage(AttributeTargets.Property)]
    public class DBFieldNameAttribute : Attribute
    {
        private string name;

        public DBFieldNameAttribute(string name)
        {
            this.name = name;
        }
        public virtual string Name {
            get { return name; }
        }
    }
    public static class UniqueIdentifier
    {
        public static string New => ObjectId.GenerateNewId().ToString();

        public static long NewAlternateId => long.Parse(DateTime.UtcNow.ToString("yyMMddHHmmssffff"));
    }
    public abstract class ParentEntity
    {
        protected ParentEntity()
        {
            _id = UniqueIdentifier.New;
        }

        [DBFieldName("_id")]
        public string Id {
            get { return _id; }
            set {
                if (string.IsNullOrEmpty(value))
                    _id = UniqueIdentifier.New;
                else
                    _id = value;
            }
        }

        private string _id;

    }
}
