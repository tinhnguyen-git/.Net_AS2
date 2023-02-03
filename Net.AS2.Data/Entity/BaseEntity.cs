using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Net.AS2.Data.Entity
{
    public partial class UserField
    {
        /// <summary>
        /// Gets or sets the key
        /// </summary>
        public string Key { get; set; }

        /// <summary>
        /// Gets or sets the value
        /// </summary>
        public string Value { get; set; }

        /// <summary>
        /// Gets or sets the store identifier
        /// </summary>
        public string StoreId { get; set; }

    }
    public abstract partial class BaseEntity : ParentEntity
    {
        protected BaseEntity()
        {
            UserFields = new List<UserField>();
        }

        public IList<UserField> UserFields { get; set; }

    }
}
