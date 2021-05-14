using System.Collections.Generic;
using System.Linq;

namespace CryptographyLabs.Extensions
{
	public static class MathEx
	{
		public static double Sum(IEnumerable<double> values)
		{
			return values.Sum();
		}
	}
}