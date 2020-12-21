using System;
using System.Buffers.Text;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace Org.BouncyCastle.Bcpg
{
    public class ArmoredOutputStream : Stream
    {
        public static readonly string HeaderVersion = "Version";

        private const int PlainTextLength = 54;

        private readonly Stream outStream;
        private byte[] encodingBuffer = new byte[(PlainTextLength * 4) / 3];
        private int encodingBufferPtr = 0;
        private Crc24 crc = new Crc24();
        private int lastb;

        private bool start = true;
        private bool clearText = false;
        private bool newLine = false;

        private string type;

        private static readonly byte[] nl = new[] { (byte)'\r', (byte)'\n' };
        private static readonly string headerStart = "-----BEGIN PGP ";
        private static readonly string headerTail = "-----";
        private static readonly string footerStart = "-----END PGP ";
        private static readonly string footerTail = "-----";

        private static readonly string Version = "BCPG C# v" + /*AssemblyInfo.Version*/"1.0";

        private readonly IDictionary<string, IList<string>> headers;

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public ArmoredOutputStream(Stream outStream)
        {
            this.outStream = outStream;
            this.headers = new Dictionary<string, IList<string>>(1);
            SetHeader(HeaderVersion, Version);
        }

        public ArmoredOutputStream(Stream outStream, IDictionary headers)
            : this(outStream)
        {
            foreach (string header in headers.Keys)
            {
                IList<string> headerList = new List<string>(1);
                headerList.Add((string)headers[header]);
                this.headers[header] = headerList;
            }
        }

        /// <summary>
        /// Set an additional header entry. Any current value(s) under the same name will be
        /// replaced by the new one. A null value will clear the entry for name.
        /// </summary>
        /// <param name="name">the name of the header entry</param>
        /// <param name="val">the value of the header entry</param>
        public void SetHeader(string name, string val)
        {
            if (val == null)
            {
                this.headers.Remove(name);
            }
            else
            {
                IList<string> valueList;
                if (!headers.TryGetValue(name, out valueList))
                {
                    valueList = new List<string>(1);
                    this.headers[name] = valueList;
                }
                else
                {
                    valueList.Clear();
                }
                valueList.Add(val);
            }
        }

        /// <summary>
        /// Set an additional header entry. The current value(s) will continue to exist together
        /// with the new one. Adding a null value has no effect.
        /// </summary>
        /// <param name="name">the name of the header entry</param>
        /// <param name="val">the value of the header entry</param>
        public void AddHeader(string name, string val)
        {
            if (val == null || name == null)
                return;

            IList<string> valueList = headers[name];
            if (valueList == null)
            {
                valueList = new List<string>(1);
                this.headers[name] = valueList;
            }
            valueList.Add(val);
        }

        /// <summary>
        /// Reset the headers to only contain a Version string (if one is present).
        /// </summary>
        public void ResetHeaders()
        {
            headers.TryGetValue(HeaderVersion, out var versions);
            headers.Clear();
            if (versions != null)
            {
                headers[HeaderVersion] = versions;
            }
        }

        /// <summary>
        /// Start a clear text signed message.
        /// </summary>
        /// <param name="hashAlgorithm">hash algorithm</param>
        public void BeginClearText(HashAlgorithmTag hashAlgorithm)
        {
            string hashName = PgpUtilities.GetDigestName(hashAlgorithm);
            DoWrite("-----BEGIN PGP SIGNED MESSAGE-----\r\n");
            DoWrite("Hash: " + hashName + "\r\n\r\n");
            clearText = true;
            newLine = true;
            lastb = 0;
        }

        public void EndClearText()
        {
            clearText = false;
        }

        public override void WriteByte(byte b)
        {
            if (clearText)
            {
                outStream.WriteByte(b);
                if (newLine)
                {
                    if (!(b == '\n' && lastb == '\r'))
                    {
                        newLine = false;
                    }
                    if (b == '-')
                    {
                        outStream.WriteByte((byte)' ');
                        outStream.WriteByte((byte)'-'); // dash escape
                    }
                }
                if (b == '\r' || (b == '\n' && lastb != '\r'))
                {
                    newLine = true;
                }
                lastb = b;
            }
            else
            {
                crc.Update(b);
                encodingBuffer[encodingBufferPtr++] = b;

                if (encodingBufferPtr == PlainTextLength)
                {
                    var status = Base64.EncodeToUtf8InPlace(encodingBuffer, encodingBufferPtr, out var bytesWritten);
                    Debug.Assert(status == System.Buffers.OperationStatus.Done);
                    outStream.Write(encodingBuffer.AsSpan(0, bytesWritten));
                    outStream.Write(nl);
                    encodingBufferPtr = 0;
                }
            }
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (clearText)
            {
                foreach (var b in buffer.AsSpan(offset, count))
                {
                    outStream.WriteByte(b);
                    if (newLine)
                    {
                        if (!(b == '\n' && lastb == '\r'))
                        {
                            newLine = false;
                        }
                        if (b == '-')
                        {
                            outStream.WriteByte((byte)' ');
                            outStream.WriteByte((byte)'-'); // dash escape
                        }
                    }
                    if (b == '\r' || (b == '\n' && lastb != '\r'))
                    {
                        newLine = true;
                    }
                    lastb = b;
                }
            }
            else if (count > 0)
            {
                if (start)
                {
                    byte b = buffer[offset];
                    bool newPacket = (b & 0x40) != 0;
                    int tag = newPacket ? b & 0x3f : (b & 0x3f) >> 2;

                    switch ((PacketTag)tag)
                    {
                        case PacketTag.PublicKey: type = "PUBLIC KEY BLOCK"; break;
                        case PacketTag.SecretKey: type = "PRIVATE KEY BLOCK"; break;
                        case PacketTag.Signature: type = "SIGNATURE"; break;
                        default: type = "MESSAGE"; break;
                    }

                    //if (!newLine)
                    //    outStream.Write(nl);
                    DoWrite(headerStart + type + headerTail);
                    outStream.Write(nl);

                    if (headers.TryGetValue(HeaderVersion, out var versions))
                    {
                        WriteHeaderEntry(HeaderVersion, versions[0].ToString());
                    }

                    foreach (var de in headers)
                    {
                        string k = de.Key;
                        if (k != HeaderVersion)
                        {
                            foreach (string v in de.Value)
                            {
                                WriteHeaderEntry(k, v);
                            }
                        }
                    }

                    outStream.Write(nl);

                    start = false;
                }

                foreach (var b in buffer.AsSpan(offset, count))
                {
                    crc.Update(b);
                    encodingBuffer[encodingBufferPtr++] = b;

                    if (encodingBufferPtr == PlainTextLength)
                    {
                        var status = Base64.EncodeToUtf8InPlace(encodingBuffer, encodingBufferPtr, out var bytesWritten);
                        Debug.Assert(status == System.Buffers.OperationStatus.Done);
                        outStream.Write(encodingBuffer.AsSpan(0, bytesWritten));
                        outStream.Write(nl);
                        encodingBufferPtr = 0;
                    }
                }
            }
        }

        /// <remarks>
        /// Close() does not close the underlying stream. So it is possible to write
        /// multiple objects using armoring to a single stream.
        /// </remarks>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (type == null)
                    return;

                DoClose();

                type = null;
                start = true;
            }
            base.Dispose(disposing);
        }

        private void DoClose()
        {
            if (encodingBufferPtr > 0)
            {
                var status = Base64.EncodeToUtf8InPlace(encodingBuffer, encodingBufferPtr, out var bytesWritten);
                Debug.Assert(status == System.Buffers.OperationStatus.Done);
                outStream.Write(encodingBuffer.AsSpan(0, bytesWritten));
                outStream.Write(nl);
                encodingBufferPtr = 0;
            }

            outStream.WriteByte((byte)'=');

            int crcV = crc.Value;
            encodingBuffer[0] = (byte)(crcV >> 16);
            encodingBuffer[1] = (byte)(crcV >> 8);
            encodingBuffer[2] = (byte)crcV;
            var crcStatus = Base64.EncodeToUtf8InPlace(encodingBuffer, 3, out var crcBytesWritten);
            Debug.Assert(crcStatus == System.Buffers.OperationStatus.Done);
            outStream.Write(encodingBuffer.AsSpan(0, crcBytesWritten));
            outStream.Write(nl);
            DoWrite(footerStart);
            DoWrite(type);
            DoWrite(footerTail);
            outStream.Write(nl);

            outStream.Flush();
        }

        private void WriteHeaderEntry(string name, string v)
        {
            DoWrite(name + ": " + v);
            outStream.Write(nl);
        }

        private void DoWrite(string s)
        {
            byte[] bs = Encoding.ASCII.GetBytes(s);
            outStream.Write(bs, 0, bs.Length);
        }

        public override void Flush()
        {
            outStream.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
