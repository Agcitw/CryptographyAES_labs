using System;
using System.Globalization;
using System.Windows.Data;

namespace CryptographyLabs.GUI
{
	internal class NotEqualsConverter : IValueConverter
	{
		public object Convert(object value, Type targetType, object parameter,
			CultureInfo culture)
		{
			var res = !value.Equals(parameter);
			return res;
		}

		public object ConvertBack(object value, Type targetType, object parameter,
			CultureInfo culture)
		{
			throw new NotSupportedException();
		}
	}
}