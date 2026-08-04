using System.Globalization;
using System.Net;
using System.Security.Cryptography;

namespace CertBaton.Contracts;

public static class LiveContractValues
{
    public const string SshSftpConnector = "ssh-sftp";
    public const string SshScpConnector = "ssh-scp";
    public const string CpanelConnector = "cpanel-api";
    public const string PleskConnector = "plesk-api";
    public const string DirectAdminConnector = "directadmin-api";
    public const string LetsEncryptStaging = "lets-encrypt-staging";
    public const string LetsEncryptProduction = "lets-encrypt-production";
    public const string UnconfiguredCertificateAuthority = "unconfigured";
    public const string LetsEncryptStagingDirectory =
        "https://acme-staging-v02.api.letsencrypt.org/directory";
    public const string LetsEncryptProductionDirectory =
        "https://acme-v02.api.letsencrypt.org/directory";
    public const int MaximumDnsNames = 100;
    public const int MaximumTargets = 500;
    public const int MaximumEvidenceRecords = 256;

    public static bool IsCertificateAuthority(string value) =>
        value is LetsEncryptStaging or LetsEncryptProduction;
}

public sealed record SshConnectionProbePayload(
    string Host,
    int Port,
    string Username,
    byte[] PrivateKey)
{
    public bool TryValidate(out string? error)
    {
        if (!TargetEnrollmentPayload.TryNormalizeHost(Host, out _) ||
            !TargetEnrollmentPayload.IsBoundedText(Username, 128) ||
            Port is < 1 or > 65_535)
        {
            error = "The SSH server address, port, or username is invalid.";
            return false;
        }

        if (PrivateKey is null ||
            PrivateKey.Length == 0 ||
            PrivateKey.Length > CredentialContractValues.MaximumSecretBytes)
        {
            error =
                $"An SSH private key must contain between 1 and {CredentialContractValues.MaximumSecretBytes} bytes.";
            return false;
        }

        error = null;
        return true;
    }
}

public sealed record SshConnectionProbeSnapshot(
    string ConnectorKind,
    string Host,
    int Port,
    string Username,
    string HostKeyAlgorithm,
    string HostKeyFingerprintSha256,
    string HostKeyBase64,
    bool AuthenticationSucceeded,
    bool SftpAvailable,
    DateTimeOffset CheckedAtUtc)
{
    public bool TryValidate(out string? error)
    {
        if (ConnectorKind != LiveContractValues.SshSftpConnector ||
            !TargetEnrollmentPayload.TryNormalizeHost(Host, out _) ||
            !TargetEnrollmentPayload.IsBoundedText(Username, 128) ||
            Port is < 1 or > 65_535 ||
            !TargetEnrollmentPayload.IsHostKeyAlgorithm(HostKeyAlgorithm) ||
            !TargetEnrollmentPayload.IsCanonicalSha256Fingerprint(
                HostKeyFingerprintSha256) ||
            !TargetEnrollmentPayload.TryValidateRawHostKey(HostKeyBase64) ||
            !TargetEnrollmentPayload.RawHostKeyMatchesFingerprint(
                HostKeyBase64,
                HostKeyFingerprintSha256) ||
            !AuthenticationSucceeded ||
            !SftpAvailable ||
            CheckedAtUtc == default ||
            CheckedAtUtc.Offset != TimeSpan.Zero)
        {
            error = "The SSH/SFTP connection test result is invalid.";
            return false;
        }

        error = null;
        return true;
    }
}

public sealed record TargetEnrollmentPayload(
    Guid EnrollmentId,
    string DisplayName,
    IReadOnlyList<string> DnsNames,
    string Host,
    int Port,
    string Username,
    Guid CredentialReference,
    string HostKeyAlgorithm,
    string HostKeyFingerprintSha256,
    string? HostKeyBase64,
    string ChallengeWebroot,
    string IncomingRoot,
    string CertificatePath,
    string PrivateKeyPath,
    string CertificateAuthority,
    string ContactEmail,
    bool TermsOfServiceAgreed,
    bool AutoRenew,
    int RenewBeforeDays,
    int CheckIntervalMinutes)
{
    public bool TryValidate(out string? error)
    {
        if (EnrollmentId == Guid.Empty ||
            CredentialReference == Guid.Empty ||
            EnrollmentId == CredentialReference)
        {
            error = "Enrollment and credential references must be distinct, non-empty GUIDs.";
            return false;
        }

        if (!IsBoundedText(DisplayName, 100) ||
            !IsBoundedText(Username, 128))
        {
            error = "The target display name or SSH username is invalid.";
            return false;
        }

        if (!TryNormalizeHost(Host, out _))
        {
            error = "The SSH host is invalid.";
            return false;
        }

        if (Port is < 1 or > 65_535)
        {
            error = "The SSH port must be between 1 and 65535.";
            return false;
        }

        if (DnsNames is null ||
            DnsNames.Count is < 1 or > LiveContractValues.MaximumDnsNames ||
            DnsNames.Any(static name => !IsDnsName(name)) ||
            DnsNames.Distinct(StringComparer.OrdinalIgnoreCase).Count() !=
                DnsNames.Count)
        {
            error = "The target must contain unique, valid, non-wildcard DNS names.";
            return false;
        }

        if (!IsHostKeyAlgorithm(HostKeyAlgorithm) ||
            !IsCanonicalSha256Fingerprint(HostKeyFingerprintSha256) ||
            !TryValidateRawHostKey(HostKeyBase64) ||
            !RawHostKeyMatchesFingerprint(
                HostKeyBase64,
                HostKeyFingerprintSha256))
        {
            error = "The SSH host-key pin is invalid.";
            return false;
        }

        if (!IsAbsolutePosixPath(ChallengeWebroot) ||
            !IsAbsolutePosixPath(IncomingRoot) ||
            !IsAbsolutePosixPath(CertificatePath) ||
            !IsAbsolutePosixPath(PrivateKeyPath) ||
            string.Equals(ChallengeWebroot, IncomingRoot, StringComparison.Ordinal) ||
            string.Equals(CertificatePath, PrivateKeyPath, StringComparison.Ordinal))
        {
            error = "The remote deployment paths are invalid or overlap.";
            return false;
        }

        if (!LiveContractValues.IsCertificateAuthority(CertificateAuthority))
        {
            error = "The certificate authority must be Let's Encrypt staging or production.";
            return false;
        }

        if (!TermsOfServiceAgreed || !IsEmailAddress(ContactEmail))
        {
            error = "A valid contact email and explicit terms acceptance are required.";
            return false;
        }

        if (RenewBeforeDays is < 1 or > 90 ||
            CheckIntervalMinutes is < 15 or > 10_080)
        {
            error = "The renewal window or check interval is outside the supported range.";
            return false;
        }

        error = null;
        return true;
    }

    internal static bool IsBoundedText(string? value, int maximumLength) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= maximumLength &&
        string.Equals(value, value.Trim(), StringComparison.Ordinal) &&
        !value.Any(char.IsControl);

    internal static bool TryNormalizeHost(string? value, out string? normalized)
    {
        normalized = null;
        if (!IsBoundedText(value, 253))
        {
            return false;
        }

        if (IPAddress.TryParse(value, out var address))
        {
            normalized = address.ToString();
            return true;
        }

        try
        {
            normalized = new IdnMapping().GetAscii(value!.TrimEnd('.'))
                .ToLowerInvariant();
            return normalized.Length is >= 1 and <= 253 &&
                Uri.CheckHostName(normalized) == UriHostNameType.Dns;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static bool IsDnsName(string? value)
    {
        if (!IsBoundedText(value, 253) ||
            value!.StartsWith("*.", StringComparison.Ordinal) ||
            IPAddress.TryParse(value, out _))
        {
            return false;
        }

        try
        {
            var ascii = new IdnMapping().GetAscii(value.TrimEnd('.'));
            return ascii.Length is >= 1 and <= 253 &&
                Uri.CheckHostName(ascii) == UriHostNameType.Dns;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    internal static bool IsHostKeyAlgorithm(string? value) =>
        value is "ssh-ed25519" or
            "ecdsa-sha2-nistp256" or
            "ecdsa-sha2-nistp384" or
            "ecdsa-sha2-nistp521" or
            "rsa-sha2-256" or
            "rsa-sha2-512";

    internal static bool IsCanonicalSha256Fingerprint(string? value)
    {
        if (string.IsNullOrEmpty(value) ||
            !value.StartsWith("SHA256:", StringComparison.Ordinal) ||
            value.Contains('=', StringComparison.Ordinal))
        {
            return false;
        }

        try
        {
            var encoded = value["SHA256:".Length..];
            var padding = new string('=', (4 - encoded.Length % 4) % 4);
            var decoded = Convert.FromBase64String(encoded + padding);
            return decoded.Length == 32 &&
                string.Equals(
                    Convert.ToBase64String(decoded).TrimEnd('='),
                    encoded,
                    StringComparison.Ordinal);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    internal static bool TryValidateRawHostKey(string? value)
    {
        if (value is null)
        {
            return false;
        }

        try
        {
            var decoded = Convert.FromBase64String(value);
            return decoded.Length is >= 32 and <= 65_536 &&
                string.Equals(
                    Convert.ToBase64String(decoded),
                    value,
                    StringComparison.Ordinal);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    internal static bool RawHostKeyMatchesFingerprint(
        string? rawHostKeyBase64,
        string fingerprintSha256)
    {
        if (rawHostKeyBase64 is null)
        {
            return false;
        }

        var rawHostKey = Convert.FromBase64String(rawHostKeyBase64);
        var encodedFingerprint = fingerprintSha256["SHA256:".Length..];
        var padding = new string(
            '=',
            (4 - encodedFingerprint.Length % 4) % 4);
        var expected = Convert.FromBase64String(encodedFingerprint + padding);
        var actual = SHA256.HashData(rawHostKey);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    private static bool IsAbsolutePosixPath(string? value)
    {
        if (!IsBoundedText(value, 1_024) ||
            !value!.StartsWith('/') ||
            value.EndsWith('/') ||
            value.Contains('\\', StringComparison.Ordinal))
        {
            return false;
        }

        return value[1..].Split('/').All(
            static segment =>
                segment.Length is >= 1 and <= 255 &&
                segment is not "." and not ".." &&
                segment.All(
                    static character =>
                        character is >= 'a' and <= 'z' or
                            >= 'A' and <= 'Z' or
                            >= '0' and <= '9' or '.' or '_' or '-' or '+'));
    }

    private static bool IsEmailAddress(string? value)
    {
        if (!IsBoundedText(value, 320) || value!.Contains(':'))
        {
            return false;
        }

        try
        {
            var parsed = new System.Net.Mail.MailAddress(value);
            return string.Equals(parsed.Address, value, StringComparison.OrdinalIgnoreCase);
        }
        catch (FormatException)
        {
            return false;
        }
    }
}

public sealed record RenewalStartPayload(Guid TargetId, Guid IdempotencyKey)
{
    public bool TryValidate(out string? error)
    {
        if (TargetId == Guid.Empty || IdempotencyKey == Guid.Empty)
        {
            error = "Target and renewal idempotency identifiers must be non-empty.";
            return false;
        }

        error = null;
        return true;
    }
}

public sealed record RenewalQueryPayload(Guid OperationId)
{
    public bool TryValidate(out string? error)
    {
        if (OperationId == Guid.Empty)
        {
            error = "The operation identifier must be non-empty.";
            return false;
        }

        error = null;
        return true;
    }
}

public sealed record TargetSnapshot(
    Guid TargetId,
    string DisplayName,
    IReadOnlyList<string> DnsNames,
    string Host,
    int Port,
    string Username,
    string HostKeyAlgorithm,
    string HostKeyFingerprintSha256,
    string CertificateAuthority,
    bool AutoRenew,
    DateTimeOffset? NextDueAtUtc,
    string Status)
{
    public bool TryValidate(out string? error)
    {
        if (TargetId == Guid.Empty ||
            string.IsNullOrWhiteSpace(DisplayName) ||
            DnsNames is null ||
            DnsNames.Count is < 1 or > LiveContractValues.MaximumDnsNames ||
            string.IsNullOrWhiteSpace(Host) ||
            Port is < 1 or > 65_535 ||
            string.IsNullOrWhiteSpace(Username) ||
            string.IsNullOrWhiteSpace(HostKeyAlgorithm) ||
            string.IsNullOrWhiteSpace(HostKeyFingerprintSha256) ||
            Status is not "ready" and not "disabled" and not "unconfigured")
        {
            error = "The target snapshot is invalid.";
            return false;
        }

        if ((Status == "ready" &&
             !LiveContractValues.IsCertificateAuthority(CertificateAuthority)) ||
            (Status == "unconfigured" &&
             CertificateAuthority !=
                LiveContractValues.UnconfiguredCertificateAuthority) ||
            (Status == "disabled" &&
             !LiveContractValues.IsCertificateAuthority(CertificateAuthority) &&
             CertificateAuthority !=
                LiveContractValues.UnconfiguredCertificateAuthority))
        {
            error = "The target snapshot certificate-authority state is invalid.";
            return false;
        }

        error = null;
        return true;
    }
}

public sealed record TargetListSnapshot(IReadOnlyList<TargetSnapshot> Targets)
{
    public bool TryValidate(out string? error)
    {
        if (Targets is null || Targets.Count > LiveContractValues.MaximumTargets)
        {
            error = "The target list is invalid or exceeds its bound.";
            return false;
        }

        foreach (var target in Targets)
        {
            if (target is null)
            {
                error = "The target list contains a null target.";
                return false;
            }

            if (!target.TryValidate(out error))
            {
                return false;
            }
        }

        error = null;
        return true;
    }
}

public sealed record RenewalEvidenceSnapshot(
    long Sequence,
    string Category,
    string Action,
    string Outcome,
    DateTimeOffset RecordedAtUtc,
    string Code,
    string Description)
{
    public bool TryValidate(out string? error)
    {
        if (Sequence <= 0 ||
            string.IsNullOrWhiteSpace(Category) ||
            string.IsNullOrWhiteSpace(Action) ||
            string.IsNullOrWhiteSpace(Outcome) ||
            RecordedAtUtc == default ||
            RecordedAtUtc.Offset != TimeSpan.Zero ||
            string.IsNullOrWhiteSpace(Code) ||
            Code.Length > 128 ||
            string.IsNullOrWhiteSpace(Description) ||
            Description.Length > 1_024)
        {
            error = "The renewal evidence snapshot is invalid.";
            return false;
        }

        error = null;
        return true;
    }
}

public sealed record RenewalOperationSnapshot(
    Guid OperationId,
    Guid TargetId,
    string Status,
    DateTimeOffset RequestedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    DateTimeOffset? CompletedAtUtc,
    string? FailureCode,
    string? CertificateLeafSha256,
    bool PublicTlsVerified,
    bool ChallengeCleanupVerified,
    IReadOnlyList<RenewalEvidenceSnapshot> Evidence)
{
    public bool TryValidate(out string? error)
    {
        if (OperationId == Guid.Empty ||
            TargetId == Guid.Empty ||
            Status is not "queued" and not "running" and not "blocked" and not
                "rollback-required" and not "succeeded" and not "failed" and not
                "cancelled" and not "interrupted" ||
            RequestedAtUtc == default ||
            UpdatedAtUtc < RequestedAtUtc ||
            RequestedAtUtc.Offset != TimeSpan.Zero ||
            UpdatedAtUtc.Offset != TimeSpan.Zero ||
            (CompletedAtUtc.HasValue && CompletedAtUtc.Value.Offset != TimeSpan.Zero) ||
            Evidence is null ||
            Evidence.Count > LiveContractValues.MaximumEvidenceRecords)
        {
            error = "The renewal operation snapshot is invalid.";
            return false;
        }

        if (Status == "succeeded" &&
            (!PublicTlsVerified || !ChallengeCleanupVerified ||
             CompletedAtUtc is null || FailureCode is not null))
        {
            error = "A successful renewal requires final verification and cleanup evidence.";
            return false;
        }

        foreach (var entry in Evidence)
        {
            if (entry is null)
            {
                error = "The renewal operation contains null evidence.";
                return false;
            }

            if (!entry.TryValidate(out error))
            {
                return false;
            }
        }

        error = null;
        return true;
    }
}
