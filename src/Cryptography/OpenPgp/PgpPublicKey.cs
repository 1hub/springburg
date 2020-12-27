using InflatablePalace.Cryptography.Algorithms;
using InflatablePalace.Cryptography.OpenPgp.Packet;
using Internal.Cryptography;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Ed25519Dsa = InflatablePalace.Cryptography.Algorithms.Ed25519;

namespace InflatablePalace.Cryptography.OpenPgp
{
    /// <summary>General class to handle a PGP public key object.</summary>
    public class PgpPublicKey : PgpEncodable, IPgpKey
    {
        private static readonly int[] MasterKeyCertificationTypes = new int[]
        {
            PgpSignature.PositiveCertification,
            PgpSignature.CasualCertification,
            PgpSignature.NoCertification,
            PgpSignature.DefaultCertification,
            PgpSignature.DirectKey,
        };

        private long keyId;
        private byte[] fingerprint;

        private AsymmetricAlgorithm key;
        internal PublicKeyPacket publicPk;
        internal TrustPacket trustPk;
        internal IList<PgpSignature> keySigs = new List<PgpSignature>();
        internal IList<object> ids = new List<object>();
        internal IList<TrustPacket> idTrusts = new List<TrustPacket>();
        internal IList<IList<PgpSignature>> idSigs = new List<IList<PgpSignature>>();
        internal IList<PgpSignature> subSigs;

        private void Init()
        {
            BcpgKey key = publicPk.Key;

            this.fingerprint = publicPk.CalculateFingerprint();

            if (publicPk.Version <= 3)
            {
                RsaPublicBcpgKey rK = (RsaPublicBcpgKey)key;
                var modulus = rK.Modulus.Value;

                this.keyId = (long)(((ulong)modulus[modulus.Length - 8] << 56)
                    | ((ulong)modulus[modulus.Length - 7] << 48)
                    | ((ulong)modulus[modulus.Length - 6] << 40)
                    | ((ulong)modulus[modulus.Length - 5] << 32)
                    | ((ulong)modulus[modulus.Length - 4] << 24)
                    | ((ulong)modulus[modulus.Length - 3] << 16)
                    | ((ulong)modulus[modulus.Length - 2] << 8)
                    | (ulong)modulus[modulus.Length - 1]);
                //this.keyId = (long)(ulong)(rK.Modulus & 0xffff_ffff_ffff_ffff);
            }
            else
            {
                this.keyId = (long)(((ulong)fingerprint[fingerprint.Length - 8] << 56)
                    | ((ulong)fingerprint[fingerprint.Length - 7] << 48)
                    | ((ulong)fingerprint[fingerprint.Length - 6] << 40)
                    | ((ulong)fingerprint[fingerprint.Length - 5] << 32)
                    | ((ulong)fingerprint[fingerprint.Length - 4] << 24)
                    | ((ulong)fingerprint[fingerprint.Length - 3] << 16)
                    | ((ulong)fingerprint[fingerprint.Length - 2] << 8)
                    | (ulong)fingerprint[fingerprint.Length - 1]);
            }
        }

        /// <summary>
        /// Create a PgpPublicKey from the passed in lightweight one.
        /// </summary>
        /// <remarks>
        /// Note: the time passed in affects the value of the key's keyId, so you probably only want
        /// to do this once for a lightweight key, or make sure you keep track of the time you used.
        /// </remarks>
        /// <param name="pubKey">Actual public key to associate.</param>
        /// <param name="time">Date of creation.</param>
        /// <exception cref="ArgumentException">If <c>pubKey</c> is not public.</exception>
        /// <exception cref="PgpException">On key creation problem.</exception>
        public PgpPublicKey(
            AsymmetricAlgorithm pubKey,
            DateTime time)
        {
            BcpgKey bcpgKey;
            PublicKeyAlgorithmTag algorithm;
            this.key = pubKey;
            if (pubKey is RSA rK)
            {
                var rKParams = rK.ExportParameters(false);
                algorithm = PublicKeyAlgorithmTag.RsaGeneral;
                bcpgKey = new RsaPublicBcpgKey(
                    new MPInteger(rKParams.Modulus),
                    new MPInteger(rKParams.Exponent));
            }
            else if (pubKey is DSA dK)
            {
                var dKParams = dK.ExportParameters(false);
                algorithm = PublicKeyAlgorithmTag.Dsa;
                bcpgKey = new DsaPublicBcpgKey(
                    new MPInteger(dKParams.P),
                    new MPInteger(dKParams.Q),
                    new MPInteger(dKParams.G),
                    new MPInteger(dKParams.Y));

            }
            else if (pubKey is X25519 x25519K)
            {
                var ecdhKParams = x25519K.ExportParameters(false);
                algorithm = PublicKeyAlgorithmTag.ECDH;
                bcpgKey = new ECDHPublicBcpgKey(
                    new Oid("1.3.6.1.4.1.3029.1.5.1"),
                    new MPInteger(new byte[] { 0x40 }.Concat(ecdhKParams.Q.X).ToArray()),
                    HashAlgorithmTag.Sha256,
                    SymmetricKeyAlgorithmTag.Aes128);
            }
            else if (pubKey is ECDiffieHellman ecdhK)
            {
                var ecdhKParams = ecdhK.ExportParameters(false);
                algorithm = PublicKeyAlgorithmTag.ECDH;
                bcpgKey = new ECDHPublicBcpgKey(
                    ecdhKParams.Curve.Oid,
                    PgpUtilities.EncodePoint(ecdhKParams.Q),
                    HashAlgorithmTag.Sha256,
                    SymmetricKeyAlgorithmTag.Aes128);
            }
            else if (pubKey is Ed25519Dsa ed25519K)
            {
                var ed25519KParams = ed25519K.ExportParameters(false);
                var pointBytes = new byte[1 + ed25519KParams.Q.X.Length];
                pointBytes[0] = 0x40;
                Array.Copy(ed25519KParams.Q.X, 0, pointBytes, 1, ed25519KParams.Q.X.Length);
                algorithm = PublicKeyAlgorithmTag.EdDsa;
                bcpgKey = new ECDsaPublicBcpgKey(
                    new Oid("1.3.6.1.4.1.11591.15.1"),
                    new MPInteger(pointBytes));
            }
            else if (pubKey is ECDsa ecdsaK)
            {
                var ecdsaKParams = ecdsaK.ExportParameters(false);
                algorithm = PublicKeyAlgorithmTag.ECDsa;
                bcpgKey = new ECDsaPublicBcpgKey(
                    ecdsaKParams.Curve.Oid,
                    PgpUtilities.EncodePoint(ecdsaKParams.Q));
            }
            else if (pubKey is ElGamal elgamalK)
            {
                var elgamalKParams = elgamalK.ExportParameters(false);
                algorithm = PublicKeyAlgorithmTag.ElGamalGeneral;
                bcpgKey = new ElGamalPublicBcpgKey(
                    new MPInteger(elgamalKParams.P),
                    new MPInteger(elgamalKParams.G),
                    new MPInteger(elgamalKParams.Y));
            }
            else
            {
                throw new PgpException("unknown key class");
            }

            this.publicPk = new PublicKeyPacket(algorithm, time, bcpgKey);
            this.ids = new List<object>();
            this.idSigs = new List<IList<PgpSignature>>();

            try
            {
                Init();
            }
            catch (IOException e)
            {
                throw new PgpException("exception calculating keyId", e);
            }
        }

        internal PgpPublicKey(PublicKeyPacket publicPk)
            : this(publicPk, new List<object>(), new List<IList<PgpSignature>>())
        {
        }

        /// <summary>Constructor for a sub-key.</summary>
        internal PgpPublicKey(
            PublicKeyPacket publicPk,
            TrustPacket trustPk,
            IList<PgpSignature> sigs)
        {
            this.publicPk = publicPk;
            this.trustPk = trustPk;
            this.subSigs = sigs;

            Init();
        }

        internal PgpPublicKey(
            PgpPublicKey key,
            TrustPacket trust,
            IList<PgpSignature> subSigs)
        {
            this.publicPk = key.publicPk;
            this.trustPk = trust;
            this.subSigs = subSigs;

            this.fingerprint = key.fingerprint;
            this.keyId = key.keyId;
        }

        /// <summary>Copy constructor.</summary>
        /// <param name="pubKey">The public key to copy.</param>
        internal PgpPublicKey(
            PgpPublicKey pubKey)
        {
            this.publicPk = pubKey.publicPk;

            this.keySigs = new List<PgpSignature>(pubKey.keySigs);
            this.ids = new List<object>(pubKey.ids);
            this.idTrusts = new List<TrustPacket>(pubKey.idTrusts);
            this.idSigs = new List<IList<PgpSignature>>(pubKey.idSigs.Count);
            for (int i = 0; i != pubKey.idSigs.Count; i++)
            {
                this.idSigs.Add(new List<PgpSignature>(pubKey.idSigs[i]));
            }

            if (pubKey.subSigs != null)
            {
                this.subSigs = new List<PgpSignature>(pubKey.subSigs.Count);
                for (int i = 0; i != pubKey.subSigs.Count; i++)
                {
                    this.subSigs.Add(pubKey.subSigs[i]);
                }
            }

            this.fingerprint = pubKey.fingerprint;
            this.keyId = pubKey.keyId;
        }

        internal PgpPublicKey(
            PublicKeyPacket publicPk,
            TrustPacket trustPk,
            IList<PgpSignature> keySigs,
            IList<object> ids,
            IList<TrustPacket> idTrusts,
            IList<IList<PgpSignature>> idSigs)
        {
            this.publicPk = publicPk;
            this.trustPk = trustPk;
            this.keySigs = keySigs;
            this.ids = ids;
            this.idTrusts = idTrusts;
            this.idSigs = idSigs;

            Init();
        }

        internal PgpPublicKey(
            PublicKeyPacket publicPk,
            IList<object> ids,
            IList<IList<PgpSignature>> idSigs)
        {
            this.publicPk = publicPk;
            this.ids = ids;
            this.idSigs = idSigs;
            Init();
        }

        /// <summary>The version of this key.</summary>
        public int Version
        {
            get { return publicPk.Version; }
        }

        /// <summary>The creation time of this key.</summary>
        public DateTime CreationTime
        {
            get { return publicPk.GetTime(); }
        }

        /// <summary>Return the trust data associated with the public key, if present.</summary>
        /// <returns>A byte array with trust data, null otherwise.</returns>
        public byte[] GetTrustData()
        {
            if (trustPk == null)
            {
                return null;
            }

            return trustPk.GetLevelAndTrustAmount().ToArray();
        }

        /// <summary>
        /// Get validity of the public key from the time of creation.
        /// </summary>
        /// <retuns>The number of valid seconds from creation time or TimeSpan.MaxValue if it never expires.</returns>
        /// <remarks>Depending on the version of the key format the precision is either to days or seconds.</remarks>
        public TimeSpan GetValidity()
        {
            if (publicPk.Version <= 3)
            {
                return TimeSpan.FromDays(publicPk.ValidDays);
            }

            if (IsMasterKey)
            {
                for (int i = 0; i != MasterKeyCertificationTypes.Length; i++)
                {
                    if (GetExpirationTimeFromSig(true, MasterKeyCertificationTypes[i], out var expiryTime))
                    {
                        return expiryTime;
                    }
                }
            }
            else
            {
                if (GetExpirationTimeFromSig(false, PgpSignature.SubkeyBinding, out var expiryTime) ||
                    GetExpirationTimeFromSig(false, PgpSignature.DirectKey, out expiryTime))
                {
                    return expiryTime;
                }
            }

            return TimeSpan.MaxValue;
        }

        private bool GetExpirationTimeFromSig(bool selfSigned, int signatureType, out TimeSpan expiryTime)
        {
            DateTime lastDate = DateTime.MinValue;

            expiryTime = TimeSpan.MinValue;
            foreach (PgpSignature sig in GetSignaturesOfType(signatureType))
            {
                if (selfSigned && sig.KeyId != this.KeyId)
                    continue;

                PgpSignatureSubpacketVector hashed = sig.GetHashedSubPackets();
                if (hashed == null)
                    continue;

                if (!hashed.HasSubpacket(SignatureSubpacketTag.KeyExpireTime))
                    continue;

                TimeSpan current = hashed.GetKeyExpirationTime();
                if (sig.KeyId == this.KeyId)
                {
                    if (sig.CreationTime > lastDate)
                    {
                        lastDate = sig.CreationTime;
                        expiryTime = current;
                    }
                }
                else if (current != TimeSpan.MaxValue && current > expiryTime)
                {
                    expiryTime = current;
                }
            }

            return expiryTime != TimeSpan.MinValue;
        }

        /// <summary>The keyId associated with the public key.</summary>
        public long KeyId
        {
            get { return keyId; }
        }

        /// <summary>The fingerprint of the key</summary>
        public byte[] GetFingerprint()
        {
            return (byte[])fingerprint.Clone();
        }

        /// <summary>
        /// Check if this key has an algorithm type that makes it suitable to use for encryption.
        /// </summary>
        /// <remarks>
        /// Note: with version 4 keys KeyFlags subpackets should also be considered when present for
        /// determining the preferred use of the key.
        /// </remarks>
        /// <returns>
        /// <c>true</c> if this key algorithm is suitable for encryption.
        /// </returns>
        public bool IsEncryptionKey
        {
            get
            {
                switch (publicPk.Algorithm)
                {
                    case PublicKeyAlgorithmTag.ECDH:
                    case PublicKeyAlgorithmTag.ElGamalEncrypt:
                    case PublicKeyAlgorithmTag.ElGamalGeneral:
                    case PublicKeyAlgorithmTag.RsaEncrypt:
                    case PublicKeyAlgorithmTag.RsaGeneral:
                        return true;
                    default:
                        return false;
                }
            }
        }

        /// <summary>True, if this could be a master key.</summary>
        public bool IsMasterKey
        {
            get { return (subSigs == null) && !(this.IsEncryptionKey && publicPk.Algorithm != PublicKeyAlgorithmTag.RsaGeneral); }
        }

        /// <summary>The algorithm code associated with the public key.</summary>
        public PublicKeyAlgorithmTag Algorithm
        {
            get { return publicPk.Algorithm; }
        }

        /// <summary>The public key contained in the object.</summary>
        /// <returns>A lightweight public key.</returns>
        /// <exception cref="PgpException">If the key algorithm is not recognised.</exception>
        private AsymmetricAlgorithm GetKey()
        {
            if (key != null)
            {
                return key;
            }

            switch (publicPk.Algorithm)
            {
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaGeneral:
                case PublicKeyAlgorithmTag.RsaSign:
                    RsaPublicBcpgKey rsaK = (RsaPublicBcpgKey)publicPk.Key;
                    return key = RSA.Create(new RSAParameters
                    {
                        Modulus = rsaK.Modulus.Value,
                        Exponent = rsaK.PublicExponent.Value
                    });
                case PublicKeyAlgorithmTag.Dsa:
                    DsaPublicBcpgKey dsaK = (DsaPublicBcpgKey)publicPk.Key;
                    return key = DSA.Create(new DSAParameters
                    {
                        Y = dsaK.Y.Value,
                        P = dsaK.P.Value,
                        Q = dsaK.Q.Value,
                        G = dsaK.G.Value,
                    });
                case PublicKeyAlgorithmTag.ECDsa:
                case PublicKeyAlgorithmTag.ECDH:
                    ECPublicBcpgKey ecK = (ECPublicBcpgKey)publicPk.Key;
                    var curve = ECCurve.CreateFromOid(ecK.CurveOid);
                    var ecParameters = new ECParameters { Curve = curve, Q = PgpUtilities.DecodePoint(ecK.EncodedPoint) };
                    key = publicPk.Algorithm == PublicKeyAlgorithmTag.ECDsa ? ECDsa.Create(ecParameters) : PgpUtilities.GetECDiffieHellman(ecParameters);
                    return key;

                case PublicKeyAlgorithmTag.EdDsa:
                    ecK = (ECPublicBcpgKey)publicPk.Key;
                    if (ecK.CurveOid.Value == "1.3.6.1.4.1.11591.15.1")
                    {
                        // FIXME: Check first byte for 0x40
                        return key = new Ed25519Dsa(ecK.EncodedPoint.Value.AsSpan(1).ToArray());
                    }
                    goto default;

                case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    ElGamalPublicBcpgKey elK = (ElGamalPublicBcpgKey)publicPk.Key;
                    return key = ElGamal.Create(new ElGamalParameters { Y = elK.Y.Value, P = elK.P.Value, G = elK.G.Value });

                default:
                    throw new PgpException("unknown public key algorithm encountered");
            }
        }

        public byte[] EncryptSessionInfo(byte[] sessionInfo)
        {
            if (!IsEncryptionKey)
                throw new PgpException("Key is not usable for encryption");

            var asymmetricAlgorithm = GetKey();

            if (asymmetricAlgorithm is RSA rsa)
            {
                return rsa.Encrypt(sessionInfo, RSAEncryptionPadding.Pkcs1);
            }

            if (asymmetricAlgorithm is ECDiffieHellman otherPartyKey)
            {
                ECDHPublicBcpgKey ecKey = (ECDHPublicBcpgKey)PublicKeyPacket.Key;

                // Generate the ephemeral key pair
                var ecCurve = ECCurve.CreateFromOid(ecKey.CurveOid);
                var ecdh = PgpUtilities.GetECDiffieHellman(ecCurve);
                var derivedKey = ecdh.DeriveKeyFromHash(
                    otherPartyKey.PublicKey,
                    PgpUtilities.GetHashAlgorithmName(ecKey.HashAlgorithm),
                    new byte[] { 0, 0, 0, 1 },
                    Rfc6637Utilities.CreateUserKeyingMaterial(PublicKeyPacket));

                derivedKey = derivedKey.AsSpan(0, PgpUtilities.GetKeySize(ecKey.SymmetricKeyAlgorithm) / 8).ToArray();

                byte[] paddedSessionData = PgpPad.PadSessionData(sessionInfo);
                byte[] C = SymmetricKeyWrap.AESKeyWrapEncrypt(derivedKey, paddedSessionData);
                var ep = ecdh.PublicKey.ExportParameters();
                byte[] VB = PgpUtilities.EncodePoint(ep.Q).GetEncoded();
                byte[] rv = new byte[VB.Length + 1 + C.Length];
                Array.Copy(VB, 0, rv, 0, VB.Length);
                rv[VB.Length] = (byte)C.Length;
                Array.Copy(C, 0, rv, VB.Length + 1, C.Length);

                return rv;
            }

            if (asymmetricAlgorithm is ElGamal elGamal)
            {
                return elGamal.Encrypt(sessionInfo, RSAEncryptionPadding.Pkcs1).ToArray();
            }

            throw new NotImplementedException();
        }

        public bool Verify(byte[] hash, byte[] signature, HashAlgorithmTag hashAlgorithm)
        {
            var key = GetKey();

            if (key is RSA rsa)
                return rsa.VerifyHash(hash, signature, PgpUtilities.GetHashAlgorithmName(hashAlgorithm), RSASignaturePadding.Pkcs1);
            if (key is DSA dsa)
                return dsa.VerifySignature(hash, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            if (key is ECDsa ecdsa)
                return ecdsa.VerifyHash(hash, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

            throw new NotImplementedException();
        }

        /// <summary>Allows enumeration of any user IDs associated with the key.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>string</c> objects.</returns>
        public IEnumerable<object> GetUserIds()
        {
            return new List<object>(ids).AsReadOnly();
        }

        /// <summary>Allows enumeration of any user attribute vectors associated with the key.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>PgpUserAttributeSubpacketVector</c> objects.</returns>
        public IEnumerable<PgpUserAttributeSubpacketVector> GetUserAttributes()
        {
            return ids.OfType<PgpUserAttributeSubpacketVector>();
        }

        /// <summary>Allows enumeration of any signatures associated with the passed in id.</summary>
        /// <param name="id">The ID to be matched.</param>
        /// <returns>An <c>IEnumerable</c> of <c>PgpSignature</c> objects.</returns>
        public IEnumerable<PgpSignature> GetSignaturesForId(string id)
        {
            if (id == null)
                throw new ArgumentNullException(nameof(id));

            for (int i = 0; i != ids.Count; i++)
            {
                if (id.Equals(ids[i]))
                {
                    return idSigs[i];
                }
            }

            return null;
        }

        /// <summary>Allows enumeration of signatures associated with the passed in user attributes.</summary>
        /// <param name="userAttributes">The vector of user attributes to be matched.</param>
        /// <returns>An <c>IEnumerable</c> of <c>PgpSignature</c> objects.</returns>
        public IEnumerable<PgpSignature> GetSignaturesForUserAttribute(PgpUserAttributeSubpacketVector userAttributes)
        {
            for (int i = 0; i != ids.Count; i++)
            {
                if (userAttributes.Equals(ids[i]))
                {
                    return idSigs[i];
                }
            }

            return null;
        }

        /// <summary>Allows enumeration of signatures of the passed in type that are on this key.</summary>
        /// <param name="signatureType">The type of the signature to be returned.</param>
        /// <returns>An <c>IEnumerable</c> of <c>PgpSignature</c> objects.</returns>
        public IEnumerable<PgpSignature> GetSignaturesOfType(
            int signatureType)
        {
            return GetSignatures().Where(sig => sig.SignatureType == signatureType);
        }

        /// <summary>Allows enumeration of all signatures/certifications associated with this key.</summary>
        /// <returns>An <c>IEnumerable</c> with all signatures/certifications.</returns>
        public IEnumerable<PgpSignature> GetSignatures()
        {
            if (subSigs != null)
                return subSigs;
            var sigs = new List<PgpSignature>(keySigs);
            foreach (IList<PgpSignature> extraSigs in idSigs)
                sigs.AddRange(extraSigs);
            return sigs;
        }

        /**
         * Return all signatures/certifications directly associated with this key (ie, not to a user id).
         *
         * @return an iterator (possibly empty) with all signatures/certifications.
         */
        public IEnumerable<PgpSignature> GetKeySignatures()
        {
            return subSigs ?? keySigs;
        }

        internal PublicKeyPacket PublicKeyPacket
        {
            get { return publicPk; }
        }

        public override void Encode(IPacketWriter outStr)
        {
            outStr.WritePacket(publicPk);

            if (trustPk != null)
            {
                outStr.WritePacket(trustPk);
            }

            if (subSigs == null)    // not a sub-key
            {
                foreach (PgpSignature keySig in keySigs)
                {
                    keySig.Encode(outStr);
                }

                for (int i = 0; i != ids.Count; i++)
                {
                    if (ids[i] is string)
                    {
                        string id = (string)ids[i];
                        outStr.WritePacket(new UserIdPacket(id));
                    }
                    else
                    {
                        PgpUserAttributeSubpacketVector v = (PgpUserAttributeSubpacketVector)ids[i];
                        outStr.WritePacket(new UserAttributePacket(v.ToSubpacketArray()));
                    }

                    if (idTrusts[i] != null)
                    {
                        outStr.WritePacket(idTrusts[i]);
                    }

                    foreach (PgpSignature sig in (IList)idSigs[i])
                    {
                        sig.Encode(outStr);
                    }
                }
            }
            else
            {
                foreach (PgpSignature subSig in subSigs)
                {
                    subSig.Encode(outStr);
                }
            }
        }

        /// <summary>Check whether this (sub)key has a revocation signature on it.</summary>
        /// <returns>True, if this (sub)key has been revoked.</returns>
        public bool IsRevoked()
        {
            int ns = 0;
            bool revoked = false;
            if (IsMasterKey)    // Master key
            {
                while (!revoked && (ns < keySigs.Count))
                {
                    if (keySigs[ns++].SignatureType == PgpSignature.KeyRevocation)
                    {
                        revoked = true;
                    }
                }
            }
            else    // Sub-key
            {
                while (!revoked && (ns < subSigs.Count))
                {
                    if (subSigs[ns++].SignatureType == PgpSignature.SubkeyRevocation)
                    {
                        revoked = true;
                    }
                }
            }
            return revoked;
        }

        /// <summary>Add a certification for an id to the given public key.</summary>
        /// <param name="key">The key the certification is to be added to.</param>
        /// <param name="id">The ID the certification is associated with.</param>
        /// <param name="certification">The new certification.</param>
        /// <returns>The re-certified key.</returns>
        public static PgpPublicKey AddCertification(
            PgpPublicKey key,
            string id,
            PgpSignature certification)
        {
            return AddCert(key, id, certification);
        }

        /// <summary>Add a certification for the given UserAttributeSubpackets to the given public key.</summary>
        /// <param name="key">The key the certification is to be added to.</param>
        /// <param name="userAttributes">The attributes the certification is associated with.</param>
        /// <param name="certification">The new certification.</param>
        /// <returns>The re-certified key.</returns>
        public static PgpPublicKey AddCertification(
            PgpPublicKey key,
            PgpUserAttributeSubpacketVector userAttributes,
            PgpSignature certification)
        {
            return AddCert(key, userAttributes, certification);
        }

        private static PgpPublicKey AddCert(
            PgpPublicKey key,
            object id,
            PgpSignature certification)
        {
            PgpPublicKey returnKey = new PgpPublicKey(key);
            IList<PgpSignature> sigList = null;

            for (int i = 0; i != returnKey.ids.Count; i++)
            {
                if (id.Equals(returnKey.ids[i]))
                {
                    sigList = returnKey.idSigs[i];
                }
            }

            if (sigList != null)
            {
                sigList.Add(certification);
            }
            else
            {
                sigList = new List<PgpSignature>();
                sigList.Add(certification);
                returnKey.ids.Add(id);
                returnKey.idTrusts.Add(null);
                returnKey.idSigs.Add(sigList);
            }

            return returnKey;
        }

        /// <summary>
        /// Remove any certifications associated with a user attribute subpacket on a key.
        /// </summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="userAttributes">The attributes to be removed.</param>
        /// <returns>
        /// The re-certified key, or null if the user attribute subpacket was not found on the key.
        /// </returns>
        public static PgpPublicKey RemoveCertification(
            PgpPublicKey key,
            PgpUserAttributeSubpacketVector userAttributes)
        {
            return RemoveCert(key, userAttributes);
        }

        /// <summary>Remove any certifications associated with a given ID on a key.</summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="id">The ID that is to be removed.</param>
        /// <returns>The re-certified key, or null if the ID was not found on the key.</returns>
        public static PgpPublicKey RemoveCertification(
            PgpPublicKey key,
            string id)
        {
            return RemoveCert(key, id);
        }

        private static PgpPublicKey RemoveCert(
            PgpPublicKey key,
            object id)
        {
            PgpPublicKey returnKey = new PgpPublicKey(key);
            bool found = false;

            for (int i = 0; i < returnKey.ids.Count; i++)
            {
                if (id.Equals(returnKey.ids[i]))
                {
                    found = true;
                    returnKey.ids.RemoveAt(i);
                    returnKey.idTrusts.RemoveAt(i);
                    returnKey.idSigs.RemoveAt(i);
                }
            }

            return found ? returnKey : null;
        }

        /// <summary>Remove a certification associated with a given ID on a key.</summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="id">The ID that the certfication is to be removed from.</param>
        /// <param name="certification">The certfication to be removed.</param>
        /// <returns>The re-certified key, or null if the certification was not found.</returns>
        public static PgpPublicKey RemoveCertification(
            PgpPublicKey key,
            string id,
            PgpSignature certification)
        {
            return RemoveCert(key, id, certification);
        }

        /// <summary>Remove a certification associated with a given user attributes on a key.</summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="userAttributes">The user attributes that the certfication is to be removed from.</param>
        /// <param name="certification">The certification to be removed.</param>
        /// <returns>The re-certified key, or null if the certification was not found.</returns>
        public static PgpPublicKey RemoveCertification(
            PgpPublicKey key,
            PgpUserAttributeSubpacketVector userAttributes,
            PgpSignature certification)
        {
            return RemoveCert(key, userAttributes, certification);
        }

        private static PgpPublicKey RemoveCert(
            PgpPublicKey key,
            object id,
            PgpSignature certification)
        {
            PgpPublicKey returnKey = new PgpPublicKey(key);
            bool found = false;

            for (int i = 0; i < returnKey.ids.Count; i++)
            {
                if (id.Equals(returnKey.ids[i]))
                {
                    IList certs = (IList)returnKey.idSigs[i];
                    found = certs.Contains(certification);

                    if (found)
                    {
                        certs.Remove(certification);
                    }
                }
            }

            return found ? returnKey : null;
        }

        /// <summary>Add a revocation or some other key certification to a key.</summary>
        /// <param name="key">The key the revocation is to be added to.</param>
        /// <param name="certification">The key signature to be added.</param>
        /// <returns>The new changed public key object.</returns>
        public static PgpPublicKey AddCertification(
            PgpPublicKey key,
            PgpSignature certification)
        {
            if (key.IsMasterKey)
            {
                if (certification.SignatureType == PgpSignature.SubkeyRevocation)
                {
                    throw new ArgumentException("signature type incorrect for master key revocation.");
                }
            }
            else
            {
                if (certification.SignatureType == PgpSignature.KeyRevocation)
                {
                    throw new ArgumentException("signature type incorrect for sub-key revocation.");
                }
            }

            PgpPublicKey returnKey = new PgpPublicKey(key);

            if (returnKey.subSigs != null)
            {
                returnKey.subSigs.Add(certification);
            }
            else
            {
                returnKey.keySigs.Add(certification);
            }

            return returnKey;
        }

        /// <summary>Remove a certification from the key.</summary>
        /// <param name="key">The key the certifications are to be removed from.</param>
        /// <param name="certification">The certfication to be removed.</param>
        /// <returns>The modified key, null if the certification was not found.</returns>
        public static PgpPublicKey RemoveCertification(
            PgpPublicKey key,
            PgpSignature certification)
        {
            PgpPublicKey returnKey = new PgpPublicKey(key);
            IList<PgpSignature> sigs = returnKey.subSigs != null
                ? returnKey.subSigs
                : returnKey.keySigs;

            //			bool found = sigs.Remove(certification);
            int pos = sigs.IndexOf(certification);
            bool found = pos >= 0;

            if (found)
            {
                sigs.RemoveAt(pos);
            }
            else
            {
                foreach (String id in key.GetUserIds())
                {
                    foreach (object sig in key.GetSignaturesForId(id))
                    {
                        // TODO Is this the right type of equality test?
                        if (certification == sig)
                        {
                            found = true;
                            returnKey = RemoveCertification(returnKey, id, certification);
                        }
                    }
                }

                if (!found)
                {
                    foreach (PgpUserAttributeSubpacketVector id in key.GetUserAttributes())
                    {
                        foreach (object sig in key.GetSignaturesForUserAttribute(id))
                        {
                            // TODO Is this the right type of equality test?
                            if (certification == sig)
                            {
                                found = true;
                                returnKey = RemoveCertification(returnKey, id, certification);
                            }
                        }
                    }
                }
            }

            return returnKey;
        }
    }
}
