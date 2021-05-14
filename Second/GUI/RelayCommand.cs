using System;
using System.Windows.Input;

namespace CryptographyLabs.GUI
{
	public class RelayCommand : ICommand
	{
		private readonly Predicate<object> _canExecute;
		private readonly Action<object> _execute;

		public RelayCommand(Action<object> execute, Predicate<object> canExecute = null)
		{
			_execute = execute ?? throw new ArgumentNullException(nameof(execute));
			_canExecute = canExecute;
		}

		event EventHandler ICommand.CanExecuteChanged
		{
			add => CommandManager.RequerySuggested += value;

			remove => CommandManager.RequerySuggested -= value;
		}

		bool ICommand.CanExecute(object parameter)
		{
			return _canExecute == null || _canExecute(parameter);
		}

		void ICommand.Execute(object parameter)
		{
			_execute(parameter);
		}
	}
}