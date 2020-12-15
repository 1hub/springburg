using Org.BouncyCastle.Bcpg.Attr;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public class PgpUserAttributeSubpacketVectorGenerator
    {
        private IList<UserAttributeSubpacket> list = new List<UserAttributeSubpacket>();

        public virtual void SetImageAttribute(
            ImageAttrib.Format imageType,
            byte[] imageData)
        {
            if (imageData == null)
                throw new ArgumentException("attempt to set null image", nameof(imageData));

            list.Add(new ImageAttrib(imageType, imageData));
        }

        public PgpUserAttributeSubpacketVector Generate()
        {
            return new PgpUserAttributeSubpacketVector(list.ToArray());
        }
    }
}
