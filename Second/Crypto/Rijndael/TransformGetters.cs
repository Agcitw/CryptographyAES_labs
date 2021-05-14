using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using CryptographyLabs.Crypto.BlockCouplingModes;

namespace CryptographyLabs.Crypto.Rijndael
{
	public static partial class Rijndael
	{
		public static ICryptoTransform Get(byte[] key, Size stateSize, byte[] iv, Mode mode, CryptoDirection direction)
		{
			return mode switch
			{
				Mode.Cbc => Cbc.Get(GetNice(key, stateSize, direction), iv, direction),
				Mode.Cfb => Cfb.Get(GetNice(key, stateSize, CryptoDirection.Encrypt), iv, direction),
				Mode.Ofb => Ofb.Get(GetNice(key, stateSize, CryptoDirection.Encrypt), iv, direction),
				_ => Get(key, stateSize, direction)
			};
		}

		public static ICryptoTransform Get(byte[] key, Size stateSize, CryptoDirection direction)
		{
			if (!IsValidKeyLength(key))
				throw new ArgumentException("Wrong key length.");

			if (direction == CryptoDirection.Encrypt)
				return new RijndaelEncryptTransform(stateSize, key);
			return new RijndaelDecryptTransform(stateSize, key);
		}

		public static INiceCryptoTransform GetNice(byte[] key, Size stateSize, CryptoDirection direction)
		{
			if (!IsValidKeyLength(key))
				throw new ArgumentException("Wrong key length.");

			if (direction == CryptoDirection.Encrypt)
				return new RijndaelEncryptTransform(stateSize, key);
			return new RijndaelDecryptTransform(stateSize, key);
		}

		private static bool IsValidKeyLength(IReadOnlyCollection<byte> key)
		{
			return key.Count is 16 or 24 or 32;
		}
	}
}