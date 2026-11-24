using System;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace ProtonVPN.Client.Logic.Auth.Tests;

[TestClass]
public class CredentialMaskingAndCentralClientTest
{
    [TestMethod]
    public void MaskAccount_MasksEmailAndPlainUsernameWithoutFullReveal()
    {
        CredentialMasking.MaskAccount("casper@proton.me").Should().Be("ca***r@pr***n.me");
        CredentialMasking.MaskAccount("bob@proton.me").Should().Be("b***b@pr***n.me");
        CredentialMasking.MaskAccount("myuser").Should().Be("my***r");
        CredentialMasking.MaskAccount("ab").Should().Be("a***");
        CredentialMasking.MaskAccount(" ").Should().BeEmpty();
        CredentialMasking.MaskedPasswordSentinel.Should().Be("••••••••••••");
    }

    [TestMethod]
    public async Task CentralCredentialClient_FetchesAndDecryptsEncryptedPayload()
    {
        string token = "pvpn_stk_windows_test_token";
        byte[] key = SHA256.HashData(Encoding.UTF8.GetBytes($"ProtonVPN.CentralCred.v1|{token}"));
        string payloadJson = JsonSerializer.Serialize(new
        {
            Alias = "Office",
            Username = "winuser@proton.me",
            Password = "WinSecretPassword!9",
            MaskedUsername = "wi***r@pr***n.me",
            PlanName = "Proton VPN Plus",
            TokenExpiresAtUtc = DateTime.UtcNow.AddHours(2),
        });
        byte[] plaintext = Encoding.UTF8.GetBytes(payloadJson);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] tag = new byte[16];
        byte[] ciphertext = new byte[plaintext.Length];
        using (AesGcm aes = new(key, 16))
        {
            aes.Encrypt(nonce, plaintext, ciphertext, tag);
        }

        string responseJson = JsonSerializer.Serialize(new
        {
            Encrypted = true,
            Algorithm = "AES-256-GCM",
            NonceBase64 = Convert.ToBase64String(nonce),
            TagBase64 = Convert.ToBase64String(tag),
            CiphertextBase64 = Convert.ToBase64String(ciphertext),
        });

        using HttpClient httpClient = new(new StubHttpMessageHandler(responseJson));
        CentralCredentialClient client = new(httpClient);

        var res = await client.FetchCredentialAsync("http://localhost:51890", token);

        res.Success.Should().BeTrue();
        res.Username.Should().Be("winuser@proton.me");
        res.Password.Should().Be("WinSecretPassword!9");
        res.MaskedUsername.Should().Be("wi***r@pr***n.me");
        res.CredentialAlias.Should().Be("Office");
    }

    private sealed class StubHttpMessageHandler : HttpMessageHandler
    {
        private readonly string _json;

        public StubHttpMessageHandler(string json) => _json = json;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_json, Encoding.UTF8, "application/json"),
            });
        }
    }
}
