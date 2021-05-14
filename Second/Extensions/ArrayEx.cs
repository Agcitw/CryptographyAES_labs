using System.Linq;

namespace CryptographyLabs.Extensions
{
	public static class ArrayEx
	{
		public static T[][] Transform<T>(T[][] values, int newRowCount)
		{
			var itemsCount = values.Sum(t => t.Length);
			var colCount = itemsCount / newRowCount;
			if (itemsCount % newRowCount != 0)
				colCount++;
			var result = new T[newRowCount][];
			for (var row = 0; row < result.Length; row++)
				result[row] = new T[colCount];
			var index = 0;
			foreach (var t in values)
				foreach (var t1 in t)
				{
					result[index / colCount][index % colCount] = t1;
					index++;
				}
			return result;
		}
	}
}