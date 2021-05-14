using System;

namespace CryptographyLabs.Crypto.Rijndael
{
	public static partial class Rijndael
	{
		public enum Size
		{
			S128,
			S192,
			S256
		}

		public static int GetBytesCount(Size size)
		{
			return size switch
			{
				Size.S192 => 24,
				Size.S256 => 32,
				_ => 16
			};
		}

		private static int GetRoundsCount(Size stateSize, Size keySize)
		{
			if (stateSize == Size.S128 && keySize == Size.S128)
				return 10;
			if (stateSize == Size.S256 || keySize == Size.S256)
				return 14;
			return 12;
		}

		private static Size SizeByBytesCount(int bytesCount)
		{
			return bytesCount switch
			{
				16 => Size.S128,
				24 => Size.S192,
				32 => Size.S256,
				_ => throw new ArgumentException("Wrong bytes count.")
			};
		}
	}
}