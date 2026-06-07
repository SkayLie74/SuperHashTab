using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace SuperHashTab
{
    // High performance CRC32 algorithm class
    public class CRC32 : HashAlgorithm
    {
        public const uint DefaultPolynomial = 0xedb88320u;
        public const uint DefaultSeed = 0xffffffffu;

        private static uint[] defaultTable;
        private readonly uint seed;
        private readonly uint[] table;
        private uint hash;

        public CRC32() : this(DefaultPolynomial, DefaultSeed) { }

        public CRC32(uint polynomial, uint seed)
        {
            table = InitializeTable(polynomial);
            this.seed = seed;
            Initialize();
        }

        public override void Initialize()
        {
            hash = seed;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            hash = CalculateHash(table, hash, array, ibStart, cbSize);
        }

        protected override byte[] HashFinal()
        {
            var hashBuffer = UInt32ToBigEndianBytes(~hash);
            HashValue = hashBuffer;
            return hashBuffer;
        }

        public override int HashSize { get { return 32; } }

        private static uint[] InitializeTable(uint polynomial)
        {
            if (polynomial == DefaultPolynomial && defaultTable != null)
                return defaultTable;

            var createTable = new uint[256];
            for (var i = 0; i < 256; i++)
            {
                var entry = (uint)i;
                for (var j = 0; j < 8; j++)
                    if ((entry & 1) == 1)
                        entry = (entry >> 1) ^ polynomial;
                    else
                        entry = entry >> 1;
                createTable[i] = entry;
            }

            if (polynomial == DefaultPolynomial)
                defaultTable = createTable;

            return createTable;
        }

        private static uint CalculateHash(uint[] table, uint seed, byte[] buffer, int start, int size)
        {
            var hash = seed;
            for (var i = start; i < start + size; i++)
                hash = (hash >> 8) ^ table[buffer[i] ^ (hash & 0xff)];
            return hash;
        }

        private static byte[] UInt32ToBigEndianBytes(uint uint32)
        {
            var result = BitConverter.GetBytes(uint32);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(result);
            return result;
        }
    }

    // High performance FIPS-202 SHA-3 algorithm class
    public class SHA3 : HashAlgorithm
    {
        private readonly int hashBitLength;
        private readonly int rate;
        private readonly byte[] state = new byte[200];
        private readonly byte[] buffer;
        private int bufferOffset;

        public SHA3(int hashBitLength)
        {
            this.hashBitLength = hashBitLength;
            this.rate = 1600 - (hashBitLength * 2);
            this.buffer = new byte[rate / 8];
            Initialize();
        }

        public override void Initialize()
        {
            Array.Clear(state, 0, state.Length);
            bufferOffset = 0;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            int limit = ibStart + cbSize;
            for (int i = ibStart; i < limit; i++)
            {
                buffer[bufferOffset++] = array[i];
                if (bufferOffset == buffer.Length)
                {
                    XorState(buffer, buffer.Length);
                    KeccakF1600();
                    bufferOffset = 0;
                }
            }
        }

        protected override byte[] HashFinal()
        {
            byte padByte = 0x06; 
            buffer[bufferOffset++] = padByte;
            while (bufferOffset < buffer.Length)
            {
                buffer[bufferOffset++] = 0;
            }
            buffer[buffer.Length - 1] |= 0x80;

            XorState(buffer, buffer.Length);
            KeccakF1600();

            byte[] hash = new byte[hashBitLength / 8];
            Array.Copy(state, hash, hash.Length);
            HashValue = hash;
            return hash;
        }

        private void XorState(byte[] data, int length)
        {
            for (int i = 0; i < length; i++)
            {
                state[i] ^= data[i];
            }
        }

        private static readonly ulong[] RoundConstants = {
            0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
            0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
            0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
            0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
            0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
            0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
        };

        private void KeccakF1600()
        {
            ulong[] a = new ulong[25];
            for (int i = 0; i < 25; i++)
            {
                a[i] = BitConverter.ToUInt64(state, i * 8);
            }

            ulong[] c = new ulong[5];
            ulong[] d = new ulong[5];
            ulong[] b = new ulong[25];

            for (int round = 0; round < 24; round++)
            {
                for (int i = 0; i < 5; i++)
                {
                    c[i] = a[i] ^ a[i + 5] ^ a[i + 10] ^ a[i + 15] ^ a[i + 20];
                }
                for (int i = 0; i < 5; i++)
                {
                    d[i] = c[(i + 4) % 5] ^ RotateLeft(c[(i + 1) % 5], 1);
                }
                for (int i = 0; i < 25; i++)
                {
                    a[i] ^= d[i % 5];
                }

                b[0] = a[0];
                b[10] = RotateLeft(a[1], 1);
                b[7] = RotateLeft(a[2], 62);
                b[11] = RotateLeft(a[3], 28);
                b[17] = RotateLeft(a[4], 27);
                b[18] = RotateLeft(a[5], 36);
                b[3] = RotateLeft(a[6], 44);
                b[5] = RotateLeft(a[7], 6);
                b[16] = RotateLeft(a[8], 8);
                b[8] = RotateLeft(a[9], 20);
                b[12] = RotateLeft(a[10], 3);
                b[2] = RotateLeft(a[11], 10);
                b[14] = RotateLeft(a[12], 43);
                b[15] = RotateLeft(a[13], 25);
                b[21] = RotateLeft(a[14], 39);
                b[24] = RotateLeft(a[15], 41);
                b[9] = RotateLeft(a[16], 45);
                b[1] = RotateLeft(a[17], 15);
                b[23] = RotateLeft(a[18], 21);
                b[19] = RotateLeft(a[19], 8);
                b[6] = RotateLeft(a[20], 18);
                b[13] = RotateLeft(a[21], 2);
                b[22] = RotateLeft(a[22], 61);
                b[4] = RotateLeft(a[23], 56);
                b[20] = RotateLeft(a[24], 14);

                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        a[i + 5 * j] = b[i + 5 * j] ^ ((~b[(i + 1) % 5 + 5 * j]) & b[(i + 2) % 5 + 5 * j]);
                    }
                }

                a[0] ^= RoundConstants[round];
            }

            for (int i = 0; i < 25; i++)
            {
                byte[] temp = BitConverter.GetBytes(a[i]);
                Array.Copy(temp, 0, state, i * 8, 8);
            }
        }

        private static ulong RotateLeft(ulong value, int offset)
        {
            return (value << offset) | (value >> (64 - offset));
        }

        public override int HashSize { get { return hashBitLength; } }
    }

    // High performance BLAKE2b algorithm class
    public class Blake2b : HashAlgorithm
    {
        private static readonly ulong[] IV = {
            0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
            0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
        };

        private static readonly byte[,] Sigma = {
            { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
            { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
            { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
            { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
            { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
            { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
            { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
            { 6, 15, 14, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5, 9 },
            { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
            { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
        };

        private readonly ulong[] h = new ulong[8];
        private readonly ulong[] t = new ulong[2];
        private readonly ulong[] f = new ulong[2];
        private readonly byte[] buffer = new byte[128];
        private int bufferLength;
        private readonly int hashSize;

        public Blake2b(int sizeBits)
        {
            hashSize = sizeBits / 8;
            Initialize();
        }

        public override void Initialize()
        {
            Array.Copy(IV, h, 8);
            h[0] ^= 0x01010000UL ^ (uint)hashSize;
            t[0] = 0; t[1] = 0;
            f[0] = 0; f[1] = 0;
            bufferLength = 0;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            int remaining = cbSize;
            int offset = ibStart;

            while (remaining > 0)
            {
                if (bufferLength == 128)
                {
                    t[0] += 128;
                    if (t[0] < 128) t[1]++;
                    Compress(buffer, 0);
                    bufferLength = 0;
                }

                int toCopy = Math.Min(remaining, 128 - bufferLength);
                Array.Copy(array, offset, buffer, bufferLength, toCopy);
                bufferLength += toCopy;
                offset += toCopy;
                remaining -= toCopy;
            }
        }

        protected override byte[] HashFinal()
        {
            t[0] += (ulong)bufferLength;
            if (t[0] < (ulong)bufferLength) t[1]++;
            f[0] = 0xffffffffffffffffUL;

            Array.Clear(buffer, bufferLength, 128 - bufferLength);
            Compress(buffer, 0);

            byte[] result = new byte[hashSize];
            for (int i = 0; i < hashSize; i++)
            {
                result[i] = (byte)(h[i / 8] >> ((i % 8) * 8));
            }
            HashValue = result;
            return result;
        }

        private void Compress(byte[] block, int offset)
        {
            ulong[] v = new ulong[16];
            ulong[] m = new ulong[16];

            for (int i = 0; i < 16; i++)
            {
                m[i] = BitConverter.ToUInt64(block, offset + i * 8);
            }

            Array.Copy(h, v, 8);
            Array.Copy(IV, 0, v, 8, 8);

            v[12] ^= t[0];
            v[13] ^= t[1];
            v[14] ^= f[0];
            v[15] ^= f[1];

            for (int round = 0; round < 12; round++)
            {
                G(v, 0, 4, 8, 12, m[Sigma[round, 0]], m[Sigma[round, 1]]);
                G(v, 1, 5, 9, 13, m[Sigma[round, 2]], m[Sigma[round, 3]]);
                G(v, 2, 6, 10, 14, m[Sigma[round, 4]], m[Sigma[round, 5]]);
                G(v, 3, 7, 11, 15, m[Sigma[round, 6]], m[Sigma[round, 7]]);
                G(v, 0, 5, 10, 15, m[Sigma[round, 8]], m[Sigma[round, 9]]);
                G(v, 1, 6, 11, 12, m[Sigma[round, 10]], m[Sigma[round, 11]]);
                G(v, 2, 7, 8, 13, m[Sigma[round, 12]], m[Sigma[round, 13]]);
                G(v, 3, 4, 9, 14, m[Sigma[round, 14]], m[Sigma[round, 15]]);
            }

            for (int i = 0; i < 8; i++)
            {
                h[i] ^= v[i] ^ v[i + 8];
            }
        }

        private static void G(ulong[] v, int a, int b, int c, int d, ulong x, ulong y)
        {
            v[a] = v[a] + v[b] + x;
            v[d] = RotateRight(v[d] ^ v[a], 32);
            v[c] = v[c] + v[d];
            v[b] = RotateRight(v[b] ^ v[c], 24);
            v[a] = v[a] + v[b] + y;
            v[d] = RotateRight(v[d] ^ v[a], 16);
            v[c] = v[c] + v[d];
            v[b] = RotateRight(v[b] ^ v[c], 63);
        }

        private static ulong RotateRight(ulong value, int offset)
        {
            return (value >> offset) | (value << (64 - offset));
        }

        public override int HashSize { get { return hashSize * 8; } }
    }

    // High performance BLAKE2s algorithm class
    public class Blake2s : HashAlgorithm
    {
        private static readonly uint[] IV = {
            0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
            0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
        };

        private static readonly byte[,] Sigma = {
            { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
            { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
            { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
            { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
            { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
            { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
            { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
            { 6, 15, 14, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5, 9 },
            { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 }
        };

        private readonly uint[] h = new uint[8];
        private readonly uint[] t = new uint[2];
        private readonly uint[] f = new uint[2];
        private readonly byte[] buffer = new byte[64];
        private int bufferLength;
        private readonly int hashSize;

        public Blake2s(int sizeBits)
        {
            hashSize = sizeBits / 8;
            Initialize();
        }

        public override void Initialize()
        {
            Array.Copy(IV, h, 8);
            h[0] ^= 0x01010000u ^ (uint)hashSize;
            t[0] = 0; t[1] = 0;
            f[0] = 0; f[1] = 0;
            bufferLength = 0;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            int remaining = cbSize;
            int offset = ibStart;

            while (remaining > 0)
            {
                if (bufferLength == 64)
                {
                    t[0] += 64;
                    if (t[0] < 64) t[1]++;
                    Compress(buffer, 0);
                    bufferLength = 0;
                }

                int toCopy = Math.Min(remaining, 64 - bufferLength);
                Array.Copy(array, offset, buffer, bufferLength, toCopy);
                bufferLength += toCopy;
                offset += toCopy;
                remaining -= toCopy;
            }
        }

        protected override byte[] HashFinal()
        {
            t[0] += (uint)bufferLength;
            if (t[0] < (uint)bufferLength) t[1]++;
            f[0] = 0xffffffffu;

            Array.Clear(buffer, bufferLength, 64 - bufferLength);
            Compress(buffer, 0);

            byte[] result = new byte[hashSize];
            for (int i = 0; i < hashSize; i++)
            {
                result[i] = (byte)(h[i / 4] >> ((i % 4) * 8));
            }
            HashValue = result;
            return result;
        }

        private void Compress(byte[] block, int offset)
        {
            uint[] v = new uint[16];
            uint[] m = new uint[16];

            for (int i = 0; i < 16; i++)
            {
                m[i] = BitConverter.ToUInt32(block, offset + i * 4);
            }

            Array.Copy(h, v, 8);
            Array.Copy(IV, 0, v, 8, 8);

            v[12] ^= t[0];
            v[13] ^= t[1];
            v[14] ^= f[0];
            v[15] ^= f[1];

            for (int round = 0; round < 10; round++)
            {
                G(v, 0, 4, 8, 12, m[Sigma[round, 0]], m[Sigma[round, 1]]);
                G(v, 1, 5, 9, 13, m[Sigma[round, 2]], m[Sigma[round, 3]]);
                G(v, 2, 6, 10, 14, m[Sigma[round, 4]], m[Sigma[round, 5]]);
                G(v, 3, 7, 11, 15, m[Sigma[round, 6]], m[Sigma[round, 7]]);
                G(v, 0, 5, 10, 15, m[Sigma[round, 8]], m[Sigma[round, 9]]);
                G(v, 1, 6, 11, 12, m[Sigma[round, 10]], m[Sigma[round, 11]]);
                G(v, 2, 7, 8, 13, m[Sigma[round, 12]], m[Sigma[round, 13]]);
                G(v, 3, 4, 9, 14, m[Sigma[round, 14]], m[Sigma[round, 15]]);
            }

            for (int i = 0; i < 8; i++)
            {
                h[i] ^= v[i] ^ v[i + 8];
            }
        }

        private static void G(uint[] v, int a, int b, int c, int d, uint x, uint y)
        {
            v[a] = v[a] + v[b] + x;
            v[d] = RotateRight(v[d] ^ v[a], 16);
            v[c] = v[c] + v[d];
            v[b] = RotateRight(v[b] ^ v[c], 12);
            v[a] = v[a] + v[b] + y;
            v[d] = RotateRight(v[d] ^ v[a], 8);
            v[c] = v[c] + v[d];
            v[b] = RotateRight(v[b] ^ v[c], 7);
        }

        private static uint RotateRight(uint value, int offset)
        {
            return (value >> offset) | (value << (32 - offset));
        }

        public override int HashSize { get { return hashSize * 8; } }
    }

    // High performance BLAKE3 algorithm class
    public class Blake3 : HashAlgorithm
    {
        private static readonly uint[] IV = {
            0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
            0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
        };

        private static readonly byte[] MSG_SCHEDULE = {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
            3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1,
            10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6,
            12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4,
            9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7,
            11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13
        };

        private const uint CHUNK_START = 1 << 0;
        private const uint CHUNK_END = 1 << 1;
        private const uint PARENT = 1 << 2;
        private const uint ROOT = 1 << 3;

        private uint[] key = new uint[8];
        private uint chunkCount = 0;
        private byte[] chunkBuffer = new byte[64];
        private int chunkBufferLength = 0;
        private readonly List<uint[]> stack = new List<uint[]>();

        public Blake3()
        {
            Initialize();
        }

        public override void Initialize()
        {
            Array.Copy(IV, key, 8);
            chunkCount = 0;
            chunkBufferLength = 0;
            stack.Clear();
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            int remaining = cbSize;
            int offset = ibStart;

            while (remaining > 0)
            {
                int toCopy = Math.Min(remaining, 64 - chunkBufferLength);
                Array.Copy(array, offset, chunkBuffer, chunkBufferLength, toCopy);
                chunkBufferLength += toCopy;
                offset += toCopy;
                remaining -= toCopy;

                if (chunkBufferLength == 64)
                {
                    uint[] chunkHash = ProcessChunk(chunkBuffer, chunkCount++, 0);
                    stack.Add(chunkHash);
                    chunkBufferLength = 0;
                }
            }
        }

        protected override byte[] HashFinal()
        {
            Array.Clear(chunkBuffer, chunkBufferLength, 64 - chunkBufferLength);
            uint[] chunkHash = ProcessChunk(chunkBuffer, chunkCount, CHUNK_END);
            stack.Add(chunkHash);

            while (stack.Count > 1)
            {
                uint[] right = stack[stack.Count - 1];
                uint[] left = stack[stack.Count - 2];
                stack.RemoveRange(stack.Count - 2, 2);
                uint[] parent = ProcessParent(left, right);
                stack.Add(parent);
            }

            byte[] result = new byte[32];
            uint[] root = stack[0];
            for (int i = 0; i < 8; i++)
            {
                byte[] bytes = BitConverter.GetBytes(root[i]);
                Array.Copy(bytes, 0, result, i * 4, 4);
            }
            HashValue = result;
            return result;
        }

        private uint[] ProcessChunk(byte[] block, uint chunkIndex, uint flags)
        {
            uint[] cv = new uint[8];
            Array.Copy(key, cv, 8);
            uint[] m = new uint[16];
            for (int i = 0; i < 16; i++) m[i] = BitConverter.ToUInt32(block, i * 4);

            uint finalFlags = flags | CHUNK_START | CHUNK_END;
            return Compress(cv, m, chunkIndex, 64, finalFlags);
        }

        private uint[] ProcessParent(uint[] left, uint[] right)
        {
            uint[] cv = new uint[8];
            Array.Copy(key, cv, 8);
            uint[] m = new uint[16];
            Array.Copy(left, 0, m, 0, 8);
            Array.Copy(right, 0, m, 8, 8);
            return Compress(cv, m, 0, 64, PARENT);
        }

        private uint[] Compress(uint[] cv, uint[] m, ulong chunkIndex, uint blockLen, uint flags)
        {
            uint[] v = new uint[16];
            Array.Copy(cv, v, 8);
            Array.Copy(IV, 0, v, 8, 4);
            v[12] = (uint)chunkIndex;
            v[13] = (uint)(chunkIndex >> 32);
            v[14] = blockLen;
            v[15] = flags;

            for (int round = 0; round < 7; round++)
            {
                int scheduleOffset = round * 16;
                G(v, 0, 4, 8, 12, m[MSG_SCHEDULE[scheduleOffset + 0]], m[MSG_SCHEDULE[scheduleOffset + 1]]);
                G(v, 1, 5, 9, 13, m[MSG_SCHEDULE[scheduleOffset + 2]], m[MSG_SCHEDULE[scheduleOffset + 3]]);
                G(v, 2, 6, 10, 14, m[MSG_SCHEDULE[scheduleOffset + 4]], m[MSG_SCHEDULE[scheduleOffset + 5]]);
                G(v, 3, 7, 11, 15, m[MSG_SCHEDULE[scheduleOffset + 6]], m[MSG_SCHEDULE[scheduleOffset + 7]]);
                G(v, 0, 5, 10, 15, m[MSG_SCHEDULE[scheduleOffset + 8]], m[MSG_SCHEDULE[scheduleOffset + 9]]);
                G(v, 1, 6, 11, 12, m[MSG_SCHEDULE[scheduleOffset + 10]], m[MSG_SCHEDULE[scheduleOffset + 11]]);
                G(v, 2, 7, 8, 13, m[MSG_SCHEDULE[scheduleOffset + 12]], m[MSG_SCHEDULE[scheduleOffset + 13]]);
                G(v, 3, 4, 9, 14, m[MSG_SCHEDULE[scheduleOffset + 14]], m[MSG_SCHEDULE[scheduleOffset + 15]]);
            }

            uint[] result = new uint[8];
            for (int i = 0; i < 8; i++)
            {
                result[i] = v[i] ^ v[i + 8];
            }
            return result;
        }

        private static void G(uint[] v, int a, int b, int c, int d, uint x, uint y)
        {
            v[a] = v[a] + v[b] + x;
            v[d] = RotateRight(v[d] ^ v[a], 16);
            v[c] = v[c] + v[d];
            v[b] = RotateRight(v[b] ^ v[c], 12);
            v[a] = v[a] + v[b] + y;
            v[d] = RotateRight(v[d] ^ v[a], 8);
            v[c] = v[c] + v[d];
            v[b] = RotateRight(v[b] ^ v[c], 7);
        }

        private static uint RotateRight(uint value, int offset)
        {
            return (value >> offset) | (value << (32 - offset));
        }

        public override int HashSize { get { return 256; } }
    }

    // High performance fuzzy spamsum (SSDEEP) algorithm class
    public static class SSDEEP
    {
        private const uint SPAMSUM_LENGTH = 64;
        private const uint MIN_BLOCKSIZE = 3;
        private const uint ROLLING_WINDOW = 7;

        private class Roll
        {
            public uint[] window = new uint[ROLLING_WINDOW];
            public uint wpos = 0;
            public uint h1 = 0;
            public uint h2 = 0;
            public uint h3 = 0;

            public void Hash(byte c)
            {
                h3 = h3 - h2 + ROLLING_WINDOW * c;
                h2 = h2 - h1 + window[wpos];
                h1 = h1 + c - window[wpos];
                window[wpos] = c;
                wpos = (wpos + 1) % ROLLING_WINDOW;
            }

            public uint Sum()
            {
                return h1 + h2 + h3;
            }
        }

        private static uint Fnv(uint hash, byte c)
        {
            return (hash * 0x01000193) ^ c;
        }

        public static string Compute(string path)
        {
            try
            {
                byte[] data = File.ReadAllBytes(path);
                if (data.Length == 0) return "";

                uint blocksize = MIN_BLOCKSIZE;
                while (blocksize * SPAMSUM_LENGTH < data.Length)
                {
                    blocksize *= 2;
                }

                while (blocksize >= MIN_BLOCKSIZE)
                {
                    string hash1 = GenerateHash(data, blocksize);
                    string hash2 = GenerateHash(data, blocksize * 2);
                    
                    if (hash1.Length >= SPAMSUM_LENGTH / 2 || blocksize == MIN_BLOCKSIZE)
                    {
                        return blocksize + ":" + hash1 + ":" + hash2;
                    }
                    blocksize /= 2;
                }
                return "";
            }
            catch
            {
                return "";
            }
        }

        private static string GenerateHash(byte[] data, uint blocksize)
        {
            StringBuilder sb = new StringBuilder();
            Roll roll = new Roll();
            uint fnv1 = 0x811C9DC5;
            uint fnv2 = 0x811C9DC5;
            string b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

            for (int i = 0; i < data.Length; i++)
            {
                byte c = data[i];
                roll.Hash(c);
                fnv1 = Fnv(fnv1, c);
                fnv2 = Fnv(fnv2, c);

                uint sum = roll.Sum();
                if (sum % blocksize == blocksize - 1)
                {
                    sb.Append(b64[(int)(fnv1 % 64)]);
                    fnv1 = 0x811C9DC5;
                }

                if (sum % (blocksize * 2) == (blocksize * 2) - 1)
                {
                    fnv2 = 0x811C9DC5;
                }
            }
            
            sb.Append(b64[(int)(fnv1 % 64)]);
            
            string res = sb.ToString();
            if (res.Length > SPAMSUM_LENGTH) res = res.Substring(0, (int)SPAMSUM_LENGTH);
            return res;
        }
    }

    // High performance fuzzy locality sensitive hashing (TLSH) algorithm class
    public static class TLSH
    {
        public static string Compute(string path)
        {
            try
            {
                byte[] data = File.ReadAllBytes(path);
                if (data.Length < 50) return "";

                int[] buckets = new int[128];
                byte[] pearson = GetPearsonTable();

                for (int i = 0; i < data.Length - 2; i++)
                {
                    byte b0 = data[i];
                    byte b1 = data[i + 1];
                    byte b2 = data[i + 2];

                    int r = pearson[b0 ^ b1];
                    int idx = pearson[r ^ b2] % 128;
                    buckets[idx]++;
                }

                int[] sortedBuckets = (int[])buckets.Clone();
                Array.Sort(sortedBuckets);
                int q1 = sortedBuckets[32];
                int q2 = sortedBuckets[64];
                int q3 = sortedBuckets[96];

                if (q3 == 0) return "";

                int lHash = LogScale(data.Length);
                int q1Ratio = (q1 * 100) / q3;
                int q2Ratio = (q2 * 100) / q3;
                int qRatio = ((q1Ratio & 0xF) << 4) | (q2Ratio & 0xF);

                StringBuilder sb = new StringBuilder();
                sb.Append(lHash.ToString("X2"));
                sb.Append(qRatio.ToString("X2"));

                for (int i = 0; i < 32; i++)
                {
                    int val = 0;
                    for (int j = 0; j < 4; j++)
                    {
                        int bucketIdx = i * 4 + j;
                        int count = buckets[bucketIdx];
                        int bitVal = 0;
                        if (count > q3) bitVal = 3;
                        else if (count > q2) bitVal = 2;
                        else if (count > q1) bitVal = 1;
                        val |= (bitVal << (j * 2));
                    }
                    sb.Append(val.ToString("X2"));
                }

                return sb.ToString().ToLower();
            }
            catch
            {
                return "";
            }
        }

        private static int LogScale(int len)
        {
            if (len <= 0) return 0;
            double val = Math.Log(len);
            int scaled = (int)(val * 10);
            return scaled & 0xFF;
        }

        private static byte[] GetPearsonTable()
        {
            byte[] table = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                table[i] = (byte)((i * 97 + 123) % 256);
            }
            return table;
        }
    }
}
