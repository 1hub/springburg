using Springburg.Cryptography.OpenPgp.Packet;
using System;
using System.Buffers;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace Springburg.Cryptography.OpenPgp
{
    class PgpSignatureTransformation : ICryptoTransform
    {
        private HashAlgorithm sig;
        private byte lastb; // Initial value anything but '\r'
        private PgpSignatureType signatureType;
        private PgpHashAlgorithm hashAlgorithm;
        private byte[]? pendingWhitespace;
        private int pendingWhitespacePosition = 0;
        private bool ignoreTrailingWhitespace;

        public PgpSignatureTransformation(PgpSignatureType signatureType, PgpHashAlgorithm hashAlgorithm, bool ignoreTrailingWhitespace)
        {
            this.signatureType = signatureType;
            this.hashAlgorithm = hashAlgorithm;
            this.lastb = 0;
            this.sig = PgpUtilities.GetHashAlgorithm(hashAlgorithm);
            this.ignoreTrailingWhitespace = ignoreTrailingWhitespace;
        }

        public PgpSignatureTransformation(SignaturePacket signaturePacket)
            : this(signaturePacket.SignatureType, signaturePacket.HashAlgorithm, false)
        {
        }

        public PgpSignatureType SignatureType => signatureType;

        public PgpHashAlgorithm HashAlgorithm => hashAlgorithm;

        bool ICryptoTransform.CanReuseTransform => true;

        bool ICryptoTransform.CanTransformMultipleBlocks => true;

        int ICryptoTransform.InputBlockSize => 1;

        int ICryptoTransform.OutputBlockSize => 1;

        private void doCanonicalUpdateByte(byte b)
        {
            if (b == '\r')
            {
                doUpdateCRLF();
            }
            else if (b == '\n')
            {
                if (lastb != '\r')
                {
                    doUpdateCRLF();
                }
            }
            else if (ignoreTrailingWhitespace && (b == ' ' || b == '\t'))
            {
                if (pendingWhitespace == null)
                {
                    pendingWhitespace = ArrayPool<byte>.Shared.Rent(128);
                }
                else if (pendingWhitespacePosition == pendingWhitespace.Length)
                {
                    var newPendingWhitespace = ArrayPool<byte>.Shared.Rent(pendingWhitespace.Length * 2);
                    pendingWhitespace.CopyTo(newPendingWhitespace, 0);
                    ArrayPool<byte>.Shared.Return(pendingWhitespace);
                    pendingWhitespace = newPendingWhitespace;
                }
                pendingWhitespace[pendingWhitespacePosition++] = b;
            }
            else
            {
                if (pendingWhitespacePosition > 0)
                {
                    Debug.Assert(pendingWhitespace != null);
                    sig.TransformBlock(pendingWhitespace, 0, pendingWhitespacePosition, null, 0);
                    pendingWhitespacePosition = 0;
                }
                sig.TransformBlock(new byte[] { b }, 0, 1, null, 0);
            }

            lastb = b;
        }

        private void doUpdateCRLF()
        {
            pendingWhitespacePosition = 0;
            sig.TransformBlock(new byte[] { (byte)'\r', (byte)'\n' }, 0, 2, null, 0);
        }

        private void Update(
            byte[] bytes,
            int off,
            int length)
        {
            if (signatureType == PgpSignatureType.CanonicalTextDocument)
            {
                int finish = off + length;

                for (int i = off; i != finish; i++)
                {
                    doCanonicalUpdateByte(bytes[i]);
                }
            }
            else
            {
                sig.TransformBlock(bytes, off, length, null, 0);
            }
        }

        public void Finish(
            int version,
            PgpPublicKeyAlgorithm keyAlgorithm,
            DateTime creationTime,
            SignatureSubpacket[] hashedSubpackets)
        {
            if (version == 3)
            {
                long time = new DateTimeOffset(creationTime, TimeSpan.Zero).ToUnixTimeSeconds();

                sig.TransformBlock(new byte[] {
                    (byte)signatureType,
                    (byte)(time >> 24),
                    (byte)(time >> 16),
                    (byte)(time >> 8),
                    (byte)(time) }, 0, 5, null, 0);
            }
            else
            {
                sig.TransformBlock(new byte[] {
                    (byte)version,
                    (byte)this.SignatureType,
                    (byte)keyAlgorithm,
                    (byte)this.HashAlgorithm }, 0, 4, null, 0);

                MemoryStream hOut = new MemoryStream();
                foreach (var hashedSubpacket in hashedSubpackets)
                {
                    hashedSubpacket.Encode(hOut);
                }

                sig.TransformBlock(new byte[] { (byte)(hOut.Length >> 8), (byte)hOut.Length }, 0, 2, null, 0);
                sig.TransformBlock(hOut.GetBuffer(), 0, (int)hOut.Length, null, 0);

                int hDataLength = 4 + (int)hOut.Length + 2;
                sig.TransformBlock(new byte[] {
                    (byte)version,
                    (byte)0xff,
                    (byte)(hDataLength >> 24),
                    (byte)(hDataLength >> 16),
                    (byte)(hDataLength >> 8),
                    (byte)(hDataLength) }, 0, 6, null, 0);
            }

            sig.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        }

        public void Finish(SignaturePacket sigPck)
        {
            Debug.Assert(sigPck.SignatureType == SignatureType);
            Finish(sigPck.Version, sigPck.KeyAlgorithm, sigPck.CreationTime, sigPck.GetHashedSubPackets());
        }

        public byte[]? Hash => sig.Hash;

        int ICryptoTransform.TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            Update(inputBuffer, inputOffset, inputCount);
            inputBuffer.AsSpan(inputOffset, inputCount).CopyTo(outputBuffer.AsSpan(outputOffset));
            return inputCount;
        }

        byte[] ICryptoTransform.TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            Update(inputBuffer, inputOffset, inputCount);
            return inputBuffer.AsSpan(inputOffset, inputCount).ToArray();
        }

        void IDisposable.Dispose()
        {
            if (pendingWhitespace != null)
            {
                ArrayPool<byte>.Shared.Return(pendingWhitespace);
                pendingWhitespace = Array.Empty<byte>();
            }
        }
    }
}
