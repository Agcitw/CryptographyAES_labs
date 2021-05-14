using System;
using System.Globalization;
using System.Numerics;

namespace CryptographyLabs.Extensions
{
	public static class StringEx
	{
		public static bool TryParse(string strValue, out ulong value)
		{
			strValue = strValue.Replace(" ", "").Replace("_", "");
			switch (strValue.Length)
			{
				case > 2 when strValue.StartsWith("0x", StringComparison.OrdinalIgnoreCase):
					try
					{
						value = Convert.ToUInt64(strValue.Substring(2), 16);
						return true;
					}
					catch
					{
						value = 0;
						return false;
					}
				case > 2 when strValue.StartsWith("0b", StringComparison.OrdinalIgnoreCase):
					try
					{
						value = Convert.ToUInt64(strValue.Substring(2), 2);
						return true;
					}
					catch
					{
						value = 0;
						return false;
					}
				default:
					return ulong.TryParse(strValue, out value);
			}
		}

		public static bool TryParse(string strValue, out byte[] bytes)
		{
			if (TryParse(strValue, out BigInteger value))
			{
				bytes = value.ToByteArray();
				if (bytes.Length > 1 && bytes[^1] == 0)
					Array.Resize(ref bytes, bytes.Length - 1);
				return true;
			}

			bytes = null;
			return false;
		}

		private static bool TryParse(string strValue, out BigInteger value)
		{
			strValue = strValue.Replace(" ", "").Replace("_", "");

			switch (strValue.Length)
			{
				case > 2 when strValue.StartsWith("0x", StringComparison.OrdinalIgnoreCase):
					strValue = strValue.Substring(2, strValue.Length - 2);
					return BigInteger.TryParse(strValue, NumberStyles.HexNumber, null, out value);
				case > 2 when strValue.StartsWith("0b", StringComparison.OrdinalIgnoreCase):
					strValue = strValue.Substring(2, strValue.Length - 2);
					return TryParseBinary(strValue, out value);
				default:
					return BigInteger.TryParse(strValue, out value);
			}
		}

		private static bool TryParseBinary(string strValue, out BigInteger value)
		{
			value = 0;
			foreach (var c in strValue)
			{
				value <<= 1;
				if (c == '1')
					value |= 1;
				else if (c != '0')
					return false;
			}
			return true;
		}
	}
}