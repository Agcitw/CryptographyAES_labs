using System;
using System.Globalization;
using System.Windows.Data;

namespace CryptographyLabs.GUI
{
	[ValueConversion(typeof(bool), typeof(bool))]
	internal class InverseBooleanConverter : IValueConverter
	{
		public object Convert(object value, Type targetType, object parameter,
			CultureInfo culture)
		{
			if (value is bool boolValue)
				return !boolValue;
			throw new InvalidOperationException("Received not bool value in boolean converter.");
		}

		public object ConvertBack(object value, Type targetType, object parameter,
			CultureInfo culture)
		{
			throw new NotSupportedException();
		}
	}
}