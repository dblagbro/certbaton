using System.Windows;

namespace CertBaton.Desktop;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        DataContext = new MainWindowViewModel();
    }

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        _ = sender;
        _ = e;

        if (DataContext is MainWindowViewModel viewModel &&
            viewModel.RefreshCommand.CanExecute(null))
        {
            viewModel.RefreshCommand.Execute(null);
        }
    }

    private async void AddSite_Click(object sender, RoutedEventArgs e)
    {
        _ = sender;
        _ = e;

        var dialog = new AddSiteWindow
        {
            Owner = this,
        };
        if (dialog.ShowDialog() == true &&
            DataContext is MainWindowViewModel viewModel &&
            viewModel.RefreshCommand.CanExecute(null))
        {
            await viewModel.RefreshCommand.ExecuteAsync(null);
        }
    }
}
