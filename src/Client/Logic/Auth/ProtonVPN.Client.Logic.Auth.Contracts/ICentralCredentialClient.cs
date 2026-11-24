using ProtonVPN.Client.Logic.Auth.Contracts.Models;

namespace ProtonVPN.Client.Logic.Auth.Contracts;

public interface ICentralCredentialClient
{
    Task<CentralTokenIssueResult> RequestSessionTokenAsync(
        string serverUrl,
        string enrollmentCode,
        string? credentialId = null,
        int expiresInMinutes = 1440,
        string? clientName = null,
        CancellationToken ct = default);

    Task<CentralCredentialFetchResult> FetchCredentialAsync(
        string serverUrl,
        string sessionToken,
        CancellationToken ct = default);
}
