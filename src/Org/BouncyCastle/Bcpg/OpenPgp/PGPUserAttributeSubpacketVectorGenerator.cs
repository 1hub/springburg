using Org.BouncyCastle.Bcpg.Attr;
using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public class PgpUserAttributeSubpacketVectorGenerator
	{
		private IList<UserAttributeSubpacket> list = new List<UserAttributeSubpacket>();

		public virtual void SetImageAttribute(
			ImageAttrib.Format	imageType,
			byte[]				imageData)
		{
			if (imageData == null)
				throw new ArgumentException("attempt to set null image", "imageData");

			list.Add(new ImageAttrib(imageType, imageData));
		}

        public virtual PgpUserAttributeSubpacketVector Generate()
		{
            UserAttributeSubpacket[] a = new UserAttributeSubpacket[list.Count];
            for (int i = 0; i < list.Count; ++i)
            {
                a[i] = (UserAttributeSubpacket)list[i];
            }
            return new PgpUserAttributeSubpacketVector(a);
		}
	}
}
