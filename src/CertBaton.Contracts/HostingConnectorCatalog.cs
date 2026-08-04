namespace CertBaton.Contracts;

[Flags]
public enum HostingConnectorCapabilities
{
    None = 0,
    ReadOnlyConnectionTest = 1 << 0,
    Http01Challenge = 1 << 1,
    CertificateTransfer = 1 << 2,
    Activation = 1 << 3,
    Rollback = 1 << 4,
    PublicTlsVerification = 1 << 5,
}

public enum HostingConnectorAvailability
{
    AvailablePreAlpha = 0,
    Planned = 1,
}

public sealed record HostingConnectorDescriptor(
    string Kind,
    string DisplayName,
    string Description,
    HostingConnectorAvailability Availability,
    HostingConnectorCapabilities Capabilities);

public static class HostingConnectorCatalog
{
    public static IReadOnlyList<HostingConnectorDescriptor> All { get; } =
        Array.AsReadOnly<HostingConnectorDescriptor>(
        [
            new(
                LiveContractValues.SshSftpConnector,
                "SSH with SFTP",
                "Secure file transfer with a constrained activation helper.",
                HostingConnectorAvailability.AvailablePreAlpha,
                HostingConnectorCapabilities.ReadOnlyConnectionTest |
                HostingConnectorCapabilities.Http01Challenge |
                HostingConnectorCapabilities.CertificateTransfer |
                HostingConnectorCapabilities.Activation |
                HostingConnectorCapabilities.Rollback |
                HostingConnectorCapabilities.PublicTlsVerification),
            new(
                LiveContractValues.SshScpConnector,
                "SSH with SCP",
                "SCP transfer with a separately qualified activation contract.",
                HostingConnectorAvailability.Planned,
                HostingConnectorCapabilities.ReadOnlyConnectionTest |
                HostingConnectorCapabilities.CertificateTransfer),
            new(
                LiveContractValues.CpanelConnector,
                "cPanel",
                "Certificate deployment through the supported cPanel API.",
                HostingConnectorAvailability.Planned,
                HostingConnectorCapabilities.CertificateTransfer |
                HostingConnectorCapabilities.Activation |
                HostingConnectorCapabilities.PublicTlsVerification),
            new(
                LiveContractValues.PleskConnector,
                "Plesk",
                "Certificate deployment through the supported Plesk API.",
                HostingConnectorAvailability.Planned,
                HostingConnectorCapabilities.CertificateTransfer |
                HostingConnectorCapabilities.Activation |
                HostingConnectorCapabilities.PublicTlsVerification),
            new(
                LiveContractValues.DirectAdminConnector,
                "DirectAdmin",
                "Certificate deployment through the supported DirectAdmin API.",
                HostingConnectorAvailability.Planned,
                HostingConnectorCapabilities.CertificateTransfer |
                HostingConnectorCapabilities.Activation |
                HostingConnectorCapabilities.PublicTlsVerification),
        ]);

    public static HostingConnectorDescriptor Find(string kind) =>
        All.SingleOrDefault(
            connector => string.Equals(
                connector.Kind,
                kind,
                StringComparison.Ordinal)) ??
        throw new ArgumentException(
            "The hosting connector kind is not registered.",
            nameof(kind));
}
