namespace ProtonVPN.Client.Logic.Auth.Contracts.Models;

public sealed record CentralTokenIssueResult(
    bool Success,
    string? SessionToken,
    string? CredentialId,
    string? CredentialAlias,
    string? MaskedUsername,
    DateTime? ExpiresAtUtc,
    string? Error);

public sealed record CentralCredentialFetchResult(
    bool Success,
    string? Username,
    string? Password,
    string? MaskedUsername,
    string? PlanName,
    string? CredentialAlias,
    DateTime? TokenExpiresAtUtc,
    string? Error);
