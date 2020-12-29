using Springburg.Cryptography.OpenPgp.Packet;
using Springburg.Cryptography.OpenPgp.Packet.UserAttribute;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;

namespace Springburg.Cryptography.OpenPgp
{
    /// <summary>Container for a list of user attribute subpackets.</summary>
    public class PgpUserAttributes
    {
        private readonly UserAttributeSubpacket[]? orginalPackets;
        private readonly IDictionary<UserAttributeSubpacketTag, UserAttributeSubpacket> packets;

        public PgpUserAttributes()
        {
            this.packets = new Dictionary<UserAttributeSubpacketTag, UserAttributeSubpacket>();
        }

        internal PgpUserAttributes(UserAttributeSubpacket[] packets)
        {
            this.orginalPackets = packets;
            this.packets = new ReadOnlyDictionary<UserAttributeSubpacketTag, UserAttributeSubpacket>(packets.ToDictionary(s => s.SubpacketType));
        }

        public byte[]? JpegImageAttribute
        {
            get
            {
                if (packets.TryGetValue(UserAttributeSubpacketTag.ImageAttribute, out var p))
                    return ((ImageAttrib)p).GetImageData();
                return null;
            }
            set
            {
                if (value == null)
                    packets.Remove(UserAttributeSubpacketTag.ImageAttribute);
                else
                    packets[UserAttributeSubpacketTag.ImageAttribute] = new ImageAttrib(ImageAttrib.Format.Jpeg, value);
            }
        }

        internal UserAttributeSubpacket[] ToSubpacketArray()
        {
            return orginalPackets ?? packets.Values.ToArray();
        }

        public override bool Equals(object? obj)
        {
            if (ReferenceEquals(obj, this))
                return true;
            if (obj is PgpUserAttributes other)
                return ToSubpacketArray().SequenceEqual(other.ToSubpacketArray());
            return false;
        }

        public override int GetHashCode()
        {
            return ToSubpacketArray().Aggregate(0, (h, p) => HashCode.Combine(h, p.GetHashCode()));
        }
    }
}
