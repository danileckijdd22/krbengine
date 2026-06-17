using System;
using Kerberos.NET.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace krbengine
{
    public class Md4Wrapper : IHashAlgorithm
    {
        private readonly MD4Digest _digest = new MD4Digest();
        public int HashSize => _digest.GetDigestSize() * 8;    
        public void Dispose() { }

        // Вычисление MD4-хеша для переданного блока данных
        public ReadOnlyMemory<byte> ComputeHash(ReadOnlyMemory<byte> data) => ComputeHash(data.Span);
        public ReadOnlyMemory<byte> ComputeHash(ReadOnlySpan<byte> data)
        {
            _digest.Reset();
            byte[] input = data.ToArray();
            _digest.BlockUpdate(input, 0, input.Length);
            
            byte[] res = new byte[_digest.GetDigestSize()];
            _digest.DoFinal(res, 0);
            return res;
        }
    }
    public class CustomLinuxCryptoPal : LinuxCryptoPal
    {
        public override IHashAlgorithm Md4() => new Md4Wrapper();
    }
    public class CustomWindowsCryptoPal : WindowsCryptoPal
    {
        public override IHashAlgorithm Md4() => new Md4Wrapper();
    }
}