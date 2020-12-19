using System;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Formats.Asn1;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Base class for an EC Public Key.</remarks>
    public abstract class ECPublicBcpgKey
        : BcpgObject, IBcpgKey
    {
        internal Oid oid;
        internal MPInteger point;

        /// <param name="bcpgIn">The stream to read the packet from.</param>
        protected ECPublicBcpgKey(
            BcpgInputStream bcpgIn)
        {
            // FIXME: THIS IS WRONG
            this.oid = new Oid(AsnDecoder.ReadObjectIdentifier(ReadBytesOfEncodedLength(bcpgIn), AsnEncodingRules.DER, out _));
            this.point = new MPInteger(bcpgIn);
        }

        /*protected ECPublicBcpgKey(
            Oid oid,
            ECPoint point)
        {
            this.point = new BigInteger(1, point.GetEncoded(false));
            this.oid = oid;
        }*/

        protected ECPublicBcpgKey(
            Oid oid,
            MPInteger encodedPoint)
        {
            this.point = encodedPoint;
            this.oid = oid;
        }

        /// <summary>The format, as a string, always "PGP".</summary>
        public string Format
        {
            get { return "PGP"; }
        }

        public override void Encode(
            BcpgOutputStream bcpgOut)
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);
            writer.WriteObjectIdentifier(this.oid.Value);
            byte[] oid = writer.Encode();
            bcpgOut.Write(oid, 1, oid.Length - 1);

            bcpgOut.WriteObject(this.point);
        }

        public virtual MPInteger EncodedPoint
        {
            get { return point; }
        }

        public virtual Oid CurveOid
        {
            get { return oid; }
        }

        protected static byte[] ReadBytesOfEncodedLength(
            BcpgInputStream bcpgIn)
        {
            int length = bcpgIn.ReadByte();
            if (length < 0)
                throw new EndOfStreamException();
            if (length == 0 || length == 0xFF)
                throw new IOException("future extensions not yet implemented");
            if (length > 127)
                throw new IOException("unsupported OID");

            byte[] buffer = new byte[length + 2];
            bcpgIn.ReadFully(buffer, 2, buffer.Length - 2);
            buffer[0] = (byte)0x06;
            buffer[1] = (byte)length;

            return buffer;
        }
    }
}
