namespace InflatablePalace.Cryptography.OpenPgp
{
    public enum PublicKeyAlgorithmTag
    {
        RsaGeneral = 1,
        RsaEncrypt = 2,
        RsaSign = 3,
        ElGamalEncrypt = 16,
        Dsa = 17,
        ECDH = 18,
        ECDsa = 19,
        ElGamalGeneral = 20,
        EdDsa = 22,
    }
}
