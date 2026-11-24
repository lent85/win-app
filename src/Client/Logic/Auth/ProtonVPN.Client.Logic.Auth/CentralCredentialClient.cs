using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ProtonVPN.Client.Logic.Auth.Contracts;
using ProtonVPN.Client.Logic.Auth.Contracts.Models;

namespace ProtonVPN.Client.Logic.Auth;

public sealed class CentralCredentialClient : ICentralCredentialClient
{
    private const int TagSizeBytes = 16;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private readonly HttpClient _httpClient;

    public CentralCredentialClient()
        : this(new HttpClient { Timeout = TimeSpan.FromSeconds(12) })
    {
    }

    public CentralCredentialClient(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<CentralTokenIssueResult> RequestSessionTokenAsync(
        string serverUrl,
        string enrollmentCode,
        string? credentialId = null,
        int expiresInMinutes = 1440,
        string? clientName = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(serverUrl))
        {
            return new CentralTokenIssueResult(false, null, null, null, null, null, "Server URL is required.");
        }

        if (string.IsNullOrWhiteSpace(enrollmentCode))
        {
            return new CentralTokenIssueResult(false, null, null, null, null, null, "Enrollment code is required.");
        }

        try
        {
            string baseUri = serverUrl.Trim().TrimEnd('/');
            var body = new
            {
                EnrollmentCode = enrollmentCode.Trim(),
                CredentialId = string.IsNullOrWhiteSpace(credentialId) ? null : credentialId.Trim(),
                ClientName = string.IsNullOrWhiteSpace(clientName) ? Environment.MachineName : clientName.Trim(),
                ExpiresInMinutes = Math.Clamp(expiresInMinutes, 1, 525600),
            };

            using HttpResponseMessage resp = await _httpClient.PostAsJsonAsync(
                $"{baseUri}/api/v1/tokens/request",
                body,
                ct);

            string raw = await resp.Content.ReadAsStringAsync(ct);
            if (!resp.IsSuccessStatusCode)
            {
                return new CentralTokenIssueResult(false, null, null, null, null, null, ExtractError(raw, resp.StatusCode));
            }

            IssuedDto? dto = JsonSerializer.Deserialize<IssuedDto>(raw, JsonOptions);
            if (dto == null || string.IsNullOrWhiteSpace(dto.SessionToken))
            {
                return new CentralTokenIssueResult(false, null, null, null, null, null, "Invalid response from server.");
            }

            return new CentralTokenIssueResult(
                true,
                dto.SessionToken,
                dto.CredentialId,
                dto.CredentialAlias,
                dto.MaskedUsername,
                dto.ExpiresAtUtc,
                null);
        }
        catch (Exception ex)
        {
            return new CentralTokenIssueResult(false, null, null, null, null, null, ex.Message);
        }
    }

    public async Task<CentralCredentialFetchResult> FetchCredentialAsync(
        string serverUrl,
        string sessionToken,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(serverUrl))
        {
            return new CentralCredentialFetchResult(false, null, null, null, null, null, null, "Server URL is required.");
        }

        if (string.IsNullOrWhiteSpace(sessionToken))
        {
            return new CentralCredentialFetchResult(false, null, null, null, null, null, null, "Session token is required.");
        }

        try
        {
            string baseUri = serverUrl.Trim().TrimEnd('/');
            string trimmedToken = sessionToken.Trim();

            using HttpRequestMessage req = new(HttpMethod.Post, $"{baseUri}/api/v1/credentials/fetch")
            {
                Content = JsonContent.Create(new { SessionToken = trimmedToken, EncryptPayload = true }),
            };
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", trimmedToken);

            using HttpResponseMessage resp = await _httpClient.SendAsync(req, ct);
            string raw = await resp.Content.ReadAsStringAsync(ct);
            if (!resp.IsSuccessStatusCode)
            {
                return new CentralCredentialFetchResult(false, null, null, null, null, null, null, ExtractError(raw, resp.StatusCode));
            }

            EnvelopeDto? envelope = JsonSerializer.Deserialize<EnvelopeDto>(raw, JsonOptions);
            if (envelope == null)
            {
                return new CentralCredentialFetchResult(false, null, null, null, null, null, null, "Invalid server response.");
            }

            PayloadDto? payload = envelope.Encrypted
                ? DecryptEnvelope(envelope, trimmedToken)
                : envelope.PlainPayload;

            if (payload == null || string.IsNullOrWhiteSpace(payload.Username) || string.IsNullOrEmpty(payload.Password))
            {
                return new CentralCredentialFetchResult(false, null, null, null, null, null, null, "Credential payload missing or empty.");
            }

            return new CentralCredentialFetchResult(
                true,
                payload.Username,
                payload.Password,
                payload.MaskedUsername,
                payload.PlanName,
                payload.Alias,
                payload.TokenExpiresAtUtc,
                null);
        }
        catch (Exception ex)
        {
            return new CentralCredentialFetchResult(false, null, null, null, null, null, null, ex.Message);
        }
    }

    private static PayloadDto? DecryptEnvelope(EnvelopeDto envelope, string sessionToken)
    {
        byte[] key = SHA256.HashData(Encoding.UTF8.GetBytes($"ProtonVPN.CentralCred.v1|{sessionToken}"));
        byte[] nonce = Convert.FromBase64String(envelope.NonceBase64 ?? string.Empty);
        byte[] tag = Convert.FromBase64String(envelope.TagBase64 ?? string.Empty);
        byte[] ciphertext = Convert.FromBase64String(envelope.CiphertextBase64 ?? string.Empty);
        byte[] plaintext = new byte[ciphertext.Length];

        using (AesGcm aes = new(key, TagSizeBytes))
        {
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
        }

        return JsonSerializer.Deserialize<PayloadDto>(Encoding.UTF8.GetString(plaintext), JsonOptions);
    }

    private static string ExtractError(string raw, System.Net.HttpStatusCode statusCode)
    {
        try
        {
            using JsonDocument doc = JsonDocument.Parse(raw);
            if (doc.RootElement.TryGetProperty("error", out JsonElement errProp))
            {
                return errProp.GetString() ?? $"HTTP {(int)statusCode}";
            }
        }
        catch
        {
            // Ignore non-JSON bodies
        }

        return string.IsNullOrWhiteSpace(raw) ? $"HTTP {(int)statusCode}" : raw;
    }

    private sealed class IssuedDto
    {
        public string? SessionToken { get; set; }
        public string? CredentialId { get; set; }
        public string? CredentialAlias { get; set; }
        public string? MaskedUsername { get; set; }
        public DateTime? ExpiresAtUtc { get; set; }
    }

    private sealed class EnvelopeDto
    {
        public bool Encrypted { get; set; }
        public string? NonceBase64 { get; set; }
        public string? TagBase64 { get; set; }
        public string? CiphertextBase64 { get; set; }
        public PayloadDto? PlainPayload { get; set; }
    }

    private sealed class PayloadDto
    {
        public string? Alias { get; set; }
        public string? Username { get; set; }
        public string? Password { get; set; }
        public string? MaskedUsername { get; set; }
        public string? PlanName { get; set; }
        public DateTime? TokenExpiresAtUtc { get; set; }
    }
}
