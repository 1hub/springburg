using InflatablePalace.Cryptography.OpenPgp.Packet;
using InflatablePalace.Cryptography.OpenPgp.Packet.Attr;
using System;
using System.Collections.Generic;
using System.Linq;

namespace InflatablePalace.Cryptography.OpenPgp
{
    public class PgpUserAttributeSubpacketVectorGenerator
    {
        private IList<UserAttributeSubpacket> list = new List<UserAttributeSubpacket>();

        public void SetImageAttribute(
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
