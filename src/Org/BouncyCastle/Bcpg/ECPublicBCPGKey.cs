using System;
using System.IO;
using System.Security.Cryptography;
using System.Formats.Asn1;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
    public abstract class ECPublicBcpgKey : BcpgKey
    {
        internal Oid oid;
        internal MPInteger point;

        /// <param name="bcpgIn">The stream to read the packet from.</param>
        protected ECPublicBcpgKey(Stream bcpgIn)
        {
            this.oid = new Oid(AsnDecoder.ReadObjectIdentifier(ReadBytesOfEncodedLength(bcpgIn), AsnEncodingRules.DER, out _));
            this.point = new MPInteger(bcpgIn);
        }

        protected ECPublicBcpgKey(
            Oid oid,
            MPInteger encodedPoint)
        {
            this.point = encodedPoint;
            this.oid = oid;
        }

        public override void Encode(Stream bcpgOut)
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);
            writer.WriteObjectIdentifier(this.oid.Value);
            byte[] oid = writer.Encode();
            bcpgOut.Write(oid, 1, oid.Length - 1);
            this.point.Encode(bcpgOut);
        }

        public virtual MPInteger EncodedPoint => point;

        public virtual Oid CurveOid => oid;

        protected static byte[] ReadBytesOfEncodedLength(Stream bcpgIn)
        {
            int length = bcpgIn.ReadByte();
            if (length < 0)
                throw new EndOfStreamException();
            if (length == 0 || length == 0xFF)
                throw new IOException("future extensions not yet implemented");
            if (length > 127)
                throw new IOException("unsupported OID");

            byte[] buffer = new byte[length + 2];
            Streams.ReadFully(bcpgIn, buffer, 2, buffer.Length - 2);
            buffer[0] = (byte)0x06;
            buffer[1] = (byte)length;

            return buffer;
        }
    }
}
