using System.ComponentModel;
using System.Windows;
using Microsoft.Win32;

namespace CertBaton.Desktop;

public partial class AddSiteWindow : Window
{
    private readonly AddSiteWizardViewModel viewModel;

    public AddSiteWindow()
    {
        InitializeComponent();
        viewModel = new AddSiteWizardViewModel();
        viewModel.PropertyChanged += ViewModel_PropertyChanged;
        DataContext = viewModel;
    }

    private void BrowseKey_Click(object sender, RoutedEventArgs e)
    {
        _ = sender;
        _ = e;

        var dialog = new OpenFileDialog
        {
            Title = "Choose the SSH private key for this hosting account",
            CheckFileExists = true,
            Multiselect = false,
            Filter =
                "SSH private keys|id_*;*.pem;*.key|All files|*.*",
        };
        if (dialog.ShowDialog(this) == true)
        {
            viewModel.PrivateKeyPath = dialog.FileName;
        }
    }

    private void ViewModel_PropertyChanged(
        object? sender,
        PropertyChangedEventArgs e)
    {
        _ = sender;
        if (e.PropertyName == nameof(AddSiteWizardViewModel.IsComplete) &&
            viewModel.IsComplete)
        {
            DialogResult = true;
        }
    }

    protected override void OnClosed(EventArgs e)
    {
        viewModel.PropertyChanged -= ViewModel_PropertyChanged;
        base.OnClosed(e);
    }
}
