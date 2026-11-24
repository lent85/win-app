namespace ProtonVPN.Client.Logic.Auth;

public static class CredentialMasking
{
    public const string MaskedPasswordSentinel = "••••••••••••";

    public static string MaskAccount(string? account)
    {
        if (string.IsNullOrWhiteSpace(account))
        {
            return string.Empty;
        }

        string trimmed = account.Trim();
        int atIdx = trimmed.IndexOf('@');
        if (atIdx > 0 && atIdx < trimmed.Length - 1)
        {
            string local = trimmed[..atIdx];
            string domain = trimmed[(atIdx + 1)..];
            return $"{MaskSegment(local)}@{MaskDomain(domain)}";
        }

        return MaskSegment(trimmed);
    }

    private static string MaskDomain(string domain)
    {
        int dotIdx = domain.LastIndexOf('.');
        if (dotIdx <= 0 || dotIdx >= domain.Length - 1)
        {
            return MaskSegment(domain);
        }

        string host = domain[..dotIdx];
        string tld = domain[dotIdx..];
        return $"{MaskSegment(host)}{tld}";
    }

    private static string MaskSegment(string seg)
    {
        if (seg.Length <= 2)
        {
            return seg[0] + "***";
        }

        if (seg.Length <= 4)
        {
            return $"{seg[0]}***{seg[^1]}";
        }

        return $"{seg[..2]}***{seg[^1]}";
    }
}
