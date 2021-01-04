using Internal.Cryptography;
using System;
using System.Formats.Asn1;
using System.Security.Cryptography;

namespace Springburg.Cryptography.OpenPgp.Keys
{
    class ECKey
    {
        protected static ECParameters ReadOpenPgpECParameters(ReadOnlySpan<byte> source, out int bytesRead)
        {
            ECParameters ecParameters = new ECParameters();

            int oidLength = source[0];
            // TODO: Validate oidLength
            var oidBytes = new byte[oidLength + 2];
            oidBytes[0] = 6;
            oidBytes[1] = (byte)oidLength;
            source.Slice(1, oidLength).CopyTo(oidBytes.AsSpan(2));
            var oid = new Oid(AsnDecoder.ReadObjectIdentifier(oidBytes, AsnEncodingRules.DER, out _));

            ecParameters.Curve = ECCurve.CreateFromOid(oid);

            var pointBytes = MPInteger.ReadInteger(source.Slice(oidLength + 1), out bytesRead);
            bytesRead += oidLength + 1;

            ecParameters.Q = DecodePoint(pointBytes);

            return ecParameters;
        }

        protected void WriteOpenPgpECParameters(ECParameters ecParameters, Span<byte> destination, out int bytesWritten)
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);
            writer.WriteObjectIdentifier(ecParameters.Curve.Oid.Value!);
            var encodedPoint = EncodePoint(ecParameters.Q, ecParameters.Curve.Oid);
            var encodedOid = writer.Encode();
            encodedOid.AsSpan(1).CopyTo(destination);
            MPInteger.TryWriteInteger(encodedPoint, destination.Slice(encodedOid.Length - 1), out bytesWritten);
            bytesWritten += encodedOid.Length - 1;
        }

        protected static ECPoint DecodePoint(ReadOnlySpan<byte> pointBytes)
        {
            if (pointBytes[0] == 4) // Uncompressed point
            {
                var expectedLength = (pointBytes.Length - 1) / 2;
                return new ECPoint { X = pointBytes.Slice(1, expectedLength).ToArray(), Y = pointBytes.Slice(expectedLength + 1, expectedLength).ToArray() };
            }
            else if (pointBytes[0] == 0x40) // Compressed point
            {
                return new ECPoint { X = pointBytes.Slice(1).ToArray(), Y = new byte[pointBytes.Length - 1] };
            }
            else
            {
                throw new CryptographicException(SR.Cryptography_OpenPgp_UnsupportedECPoint);
            }
        }

        protected static byte[] EncodePoint(ECPoint point, Oid curveOid)
        {
            // X25519 / Ed25519 use compressed points
            if (curveOid.Value == "1.3.6.1.4.1.3029.1.5.1" ||
                curveOid.Value == "1.3.6.1.4.1.11591.15.1")
            {
                var pointBytes = new byte[1 + point.X!.Length];
                pointBytes[0] = 0x40;
                Array.Copy(point.X, 0, pointBytes, 1, point.X.Length);
                return pointBytes;
            }
            else
            {
                var pointBytes = new byte[1 + point.X!.Length + point.Y!.Length];
                pointBytes[0] = 4;
                Array.Copy(point.X, 0, pointBytes, 1, point.X.Length);
                Array.Copy(point.Y, 0, pointBytes, 1 + point.X.Length, point.Y.Length);
                return pointBytes;
            }
        }
    }
}
