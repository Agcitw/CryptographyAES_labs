namespace CryptographyLabs.Crypto.Rijndael
{
	public static partial class Rijndael
	{
		public static byte[] GenerateSBox()
		{
			byte[] matrix =
			{
				0b1111_0001,
				0b1110_0011,
				0b1100_0111,
				0b1000_1111,
				0b0001_1111,
				0b0011_1110,
				0b0111_1100,
				0b1111_1000
			};

			byte[] sBox = new byte[256];
			for (var i = 0; i < 256; ++i)
			{
				var inv = Gf.Inverse((byte) i);
				for (var j = 0; j < 8; j++)
				{
					var conj = (byte) (matrix[j] & inv);
					var xorSum = BitOperations.XorBits(conj);
					sBox[i] |= (byte) (xorSum << j);
				}

				sBox[i] ^= 0x63;
			}

			return sBox;
		}

		public static byte[] GenerateInvSBox(byte[] sBox)
		{
			var invSBox = new byte[256];
			for (var i = 0; i < 256; ++i)
				invSBox[sBox[i]] = (byte) i;
			return invSBox;
		}
	}
}