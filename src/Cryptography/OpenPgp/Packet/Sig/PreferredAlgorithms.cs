using System;
using System.Linq;

namespace InflatablePalace.Cryptography.OpenPgp.Packet.Sig
{
    class PreferredAlgorithms : SignatureSubpacket
    {
        public PreferredAlgorithms(SignatureSubpacketTag type, bool critical, bool isLongLength, byte[] data)
            : base(type, critical, isLongLength, data)
        {
        }

        public PreferredAlgorithms(SignatureSubpacketTag type, bool critical, byte[] data)
            : base(type, critical, false, data)
        {
        }

        public T[] GetPreferences<T>()
            where T : Enum
        {
            return data.Cast<T>().ToArray();
        }
    }
}
