using System.Diagnostics;

namespace CryptographyLabs
{
	public static class Gf
	{
		private const bool DefaultWithReplace = true;
		private const ushort M = 0b1_0001_1011;
		private static byte[,] _divideMtx;
		private static byte[] _inverseVector;
		private static byte[,] _multiplyMtx;

		public static byte Divide(byte a, byte b, bool withReplaceMtx = DefaultWithReplace)
		{
			if (!withReplaceMtx) return Divide_(a, b);
			if (_divideMtx is null)
				CalcDivideMatrix();
			Debug.Assert(_divideMtx != null, nameof(_divideMtx) + " != null");
			return _divideMtx[a, b];
		}

		private static void CalcDivideMatrix()
		{
			if (_inverseVector is null)
				CalcInverseVector();
			_divideMtx = new byte[256, 256];
			for (var row = 0; row < 256; row++)
			for (var col = 0; col < 256; col++)
				if (_inverseVector != null)
					_divideMtx[row, col] = Multiply_((byte) row, _inverseVector[col]);
		}

		private static byte Divide_(byte a, byte b)
		{
			return Multiply_(a, Inverse_(b));
		}

		public static byte Inverse(byte a, bool withReplaceVector = DefaultWithReplace)
		{
			if (!withReplaceVector) return Inverse_(a);
			if (_inverseVector is null)
				CalcInverseVector();
			return _inverseVector?[a] ?? Inverse_(a);
		}

		private static void CalcInverseVector()
		{
			_inverseVector = new byte[256];
			for (var i = 0; i < 256; i++)
				_inverseVector[i] = Inverse_((byte) i);
		}

		private static byte Inverse_(byte a)
		{
			if (a == 0)
				return 0;
			var res = a;
			for (var i = 2; i <= 254; ++i)
				res = Multiply(res, a);
			return res;
		}

		public static byte Multiply(byte a, byte b, bool withReplaceMtx = DefaultWithReplace)
		{
			if (!withReplaceMtx) return Multiply_(a, b);
			if (_multiplyMtx is null)
				CalcMultiplyMtx();
			Debug.Assert(_multiplyMtx != null, nameof(_multiplyMtx) + " != null");
			return _multiplyMtx[a, b];
		}

		private static void CalcMultiplyMtx()
		{
			_multiplyMtx = new byte[256, 256];
			for (var row = 0; row < 256; row++)
			for (var col = 0; col < 256; col++)
				_multiplyMtx[row, col] = Multiply_((byte) row, (byte) col);
		}

		private static byte Multiply_(byte a, byte b)
		{
			ushort tm = b;
			ushort res = 0;
			do
			{
				if ((a & 1) == 1)
					res ^= tm;
				a >>= 1;
				tm <<= 1;
			} while (a > 0);
			return Mod(res);
		}

		public static byte Mod(ushort a)
		{
			const int mDeg = 8;
			var mod = a;
			while (true)
			{
				var degree = DegreeOf(mod);
				if (degree < mDeg)
					break;
				var shift = degree - mDeg;
				mod ^= (ushort) (M << shift);
			}
			return (byte) mod;
		}

		private static int DegreeOf(ushort gfValue)
		{
			var degree = 0;
			while (true)
			{
				gfValue >>= 1;
				if (gfValue == 0)
					break;
				degree++;
			}
			return degree;
		}
	}
}