using Springburg.Cryptography.OpenPgp.Packet;
using System.IO;

namespace Springburg.Cryptography.OpenPgp
{
    /// <summary>General class to handle a PGP public key object.</summary>
    public class PgpPublicKey : PgpKey
    {
        internal PgpPublicKey(PublicKeyPacket publicPk)
            : base(publicPk)
        {
        }

        internal PgpPublicKey(IPacketReader packetReader, PublicKeyPacket publicKeyPacket, bool subKey)
            : base(packetReader, publicKeyPacket, subKey)
        {
        }

        internal PgpPublicKey(PgpPublicKey publicKey)
            : base(publicKey)
        {
        }

        public PgpPublicKey(PgpSecretKey secretKey)
            : base(secretKey)
        {
            this.keyPacket = this.keyPacket is SecretSubkeyPacket secretSubkeyPacket ?
                new PublicSubkeyPacket(secretSubkeyPacket) :
                new PublicKeyPacket((SecretKeyPacket)this.keyPacket);
        }

        protected override PgpKey CreateMutableCopy() => new PgpPublicKey(this);

        public byte[] GetEncoded()
        {
            using MemoryStream bOut = new MemoryStream();
            Encode(new PacketWriter(bOut));
            return bOut.ToArray();
        }

        public void Encode(Stream s)
        {
            Encode(new PacketWriter(s));
        }
    }
}
