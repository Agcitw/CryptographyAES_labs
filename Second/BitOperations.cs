using System;

namespace CryptographyLabs
{
	public static class BitOperations
	{
		private static readonly byte[] Deltas64 = {1, 2, 4, 8, 16, 32, 16, 8, 4, 2, 1};

		public static ulong SwapBitsMasks64(ulong value, ulong[] masks)
		{
			if (Deltas64.Length != masks.Length)
				throw new ArgumentException($"Count of masks must be {Deltas64.Length}");
			for (var i = 0; i < Deltas64.Length; ++i)
			{
				var mask = masks[i];
				if (mask != 0)
					value = SwapBitsMask(value, Deltas64[i], mask);
			}
			return value;
		}

		private static ulong SwapBitsMask(ulong x, int delta, ulong mask)
		{
			var y = (x ^ (x >> delta)) & mask;
			return x ^ y ^ (y << delta);
		}
		
		public static byte XorBits(uint value, byte p)
		{
			if (p > 5)
				p = 5;
			var tm = (byte) (1 << (p - 1));
			while (tm > 0)
			{
				value ^= value >> tm;
				tm /= 2;
			}
			return (byte) (value & 1);
		}

		public static byte XorBits(byte value)
		{
			const byte p = 3;
			var tm = (byte) (1 << (p - 1));
			while (tm > 0)
			{
				value ^= (byte) (value >> tm);
				tm /= 2;
			}
			return (byte) (value & 1);
		}

		public static uint CycleShiftLeft(uint a, byte len, byte n)
		{
			n %= len;
			return ((a << n) | (a >> (len - n))) & ((1u << len) - 1);
		}
	}
}