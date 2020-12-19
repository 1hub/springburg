using System;
using System.Text;

namespace Org.BouncyCastle.Bcpg.Sig
{
    public class SignerUserId : SignatureSubpacket
    {
        public SignerUserId(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.SignerUserId, critical, isLongLength, data)
        {
        }

        public SignerUserId(bool critical, string userId)
            : base(SignatureSubpacketTag.SignerUserId, critical, false, Encoding.UTF8.GetBytes(userId))
        {
        }

        public string GetId() => Encoding.UTF8.GetString(data);
    }
}
