using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>
    /// General class for reading a PGP object stream.
    /// </summary>
    /// <remarks>
    /// Note: if this class finds a PgpPublicKey or a PgpSecretKey it
    /// will create a PgpPublicKeyRing, or a PgpSecretKeyRing for each
    /// key found. If all you are trying to do is read a key ring file use
    /// either PgpPublicKeyRingBundle or PgpSecretKeyRingBundle.
    /// </remarks>
    public class PgpObjectFactory
    {
        private readonly BcpgInputStream bcpgIn;

        public PgpObjectFactory(
            Stream inputStream)
        {
            this.bcpgIn = BcpgInputStream.Wrap(inputStream);
        }

        public PgpObjectFactory(
            byte[] bytes)
            : this(new MemoryStream(bytes, false))
        {
        }

        /// <summary>Return the next object in the stream, or null if the end is reached.</summary>
        /// <exception cref="IOException">On a parse error</exception>
        public PgpObject NextPgpObject()
        {
            PacketTag tag = bcpgIn.NextPacketTag();

            if ((int)tag == -1) return null;

            switch (tag)
            {
                case PacketTag.Signature:
                    {
                        IList<PgpSignature> l = new List<PgpSignature>();

                        while (bcpgIn.NextPacketTag() == PacketTag.Signature)
                        {
                            try
                            {
                                l.Add(new PgpSignature((SignaturePacket)bcpgIn.ReadPacket()));
                            }
                            catch (PgpException e)
                            {
                                throw new IOException("can't create signature object: " + e);
                            }
                        }

                        return new PgpSignatureList(l.ToArray());
                    }
                case PacketTag.SecretKey:
                    try
                    {
                        return new PgpSecretKeyRing(bcpgIn);
                    }
                    catch (PgpException e)
                    {
                        throw new IOException("can't create secret key object: " + e);
                    }
                case PacketTag.PublicKey:
                    return new PgpPublicKeyRing(bcpgIn);
                // TODO Make PgpPublicKey a PgpObject or return a PgpPublicKeyRing
                //				case PacketTag.PublicSubkey:
                //					return PgpPublicKeyRing.ReadSubkey(bcpgIn);
                case PacketTag.CompressedData:
                    return new PgpCompressedData((CompressedDataPacket)bcpgIn.ReadPacket());
                case PacketTag.LiteralData:
                    return new PgpLiteralData((LiteralDataPacket)bcpgIn.ReadPacket());
                case PacketTag.PublicKeyEncryptedSession:
                case PacketTag.SymmetricKeyEncryptedSessionKey:
                    return new PgpEncryptedDataList(bcpgIn);
                case PacketTag.OnePassSignature:
                    {
                        IList<PgpOnePassSignature> l = new List<PgpOnePassSignature>();

                        while (bcpgIn.NextPacketTag() == PacketTag.OnePassSignature)
                        {
                            try
                            {
                                l.Add(new PgpOnePassSignature((OnePassSignaturePacket)bcpgIn.ReadPacket()));
                            }
                            catch (PgpException e)
                            {
                                throw new IOException("can't create one pass signature object: " + e);
                            }
                        }

                        return new PgpOnePassSignatureList(l.ToArray());
                    }
                case PacketTag.Marker:
                    return new PgpMarker((MarkerPacket)bcpgIn.ReadPacket());
                case PacketTag.Experimental1:
                case PacketTag.Experimental2:
                case PacketTag.Experimental3:
                case PacketTag.Experimental4:
                    return new PgpExperimental((ExperimentalPacket)bcpgIn.ReadPacket());
            }

            throw new IOException("unknown object in stream " + bcpgIn.NextPacketTag());
        }

        /// <summary>
        /// Return all available objects in a list.
        /// </summary>
        /// <returns>An <c>IList</c> containing all objects from this factory, in order.</returns>
        public IList<PgpObject> AllPgpObjects()
        {
            IList<PgpObject> result = new List<PgpObject>();
            PgpObject pgpObject;
            while ((pgpObject = NextPgpObject()) != null)
            {
                result.Add(pgpObject);
            }
            return result;
        }

        /// <summary>
        /// Read all available objects, returning only those that are assignable to the specified type.
        /// </summary>
        /// <param name="type">The type of objects to return. All other objects are ignored.</param>
        /// <returns>An <c>IList</c> containing the filtered objects from this factory, in order.</returns>
        public IList<T> FilterPgpObjects<T>()
            where T : PgpObject
        {
            IList<T> result = new List<T>();
            PgpObject pgpObject;
            while ((pgpObject = NextPgpObject()) != null)
            {
                if (pgpObject is T castedObject)
                {
                    result.Add(castedObject);
                }
            }
            return result;
        }
    }
}
