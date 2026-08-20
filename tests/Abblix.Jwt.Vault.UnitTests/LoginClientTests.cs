// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Abblix.Jwt.Vault.UnitTests;

/// <summary>
/// The login client's contract with the lifecycle loop: every call answers with a verdict, and the
/// request it sends is the one the auth method's mount expects.
/// </summary>
public sealed class LoginClientTests : IDisposable
{
    private readonly List<IDisposable> _disposables = [];

    private (LoginClient Client, StubHttpMessageHandler Transport) ClientOver(
        VaultTransitOptions options,
        Func<HttpRequestMessage, string, HttpResponseMessage> responder)
    {
        var transport = new StubHttpMessageHandler(responder);
        var httpClient = new HttpClient(transport) { BaseAddress = new Uri("https://vault.test/v1/") };
        _disposables.Add(httpClient);
        var client = new LoginClient(
            NullLogger<LoginClient>.Instance,
            new StubHttpClientFactory(httpClient),
            new OptionsMonitorStub(options));
        return (client, transport);
    }

    private static HttpResponseMessage AuthResponse(string token, long leaseSeconds, bool renewable)
        => StubHttpMessageHandler.Json(HttpStatusCode.OK, new
        {
            auth = new { client_token = token, lease_duration = leaseSeconds, renewable },
        });

    public void Dispose()
    {
        foreach (var disposable in _disposables)
            disposable.Dispose();
    }

    [Fact]
    public async Task Login_Kubernetes_SendsTheRoleAndTheTokenFile_ToTheConfiguredMount()
    {
        var tokenFile = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        // The trailing newline is what the projected file actually carries; it must not travel.
        await File.WriteAllTextAsync(
            tokenFile, "header.payload.signature\n", TestContext.Current.CancellationToken);
        try
        {
            var (client, transport) = ClientOver(
                new VaultTransitOptions
                {
                    Authentication = new VaultAuthenticationOptions
                    {
                        Kubernetes = new KubernetesAuthenticationOptions
                        {
                            Role = "signer",
                            ServiceAccountTokenPath = tokenFile,
                        },
                    },
                },
                (_, _) => AuthResponse("s.k8s", 3600, renewable: true));

            var lease = await client.LoginAsync(TestContext.Current.CancellationToken);

            Assert.NotNull(lease);
            Assert.Equal("s.k8s", lease.Token);
            Assert.Equal(TimeSpan.FromHours(1), lease.LeaseDuration);
            Assert.True(lease.Renewable);

            Assert.Equal("/v1/auth/kubernetes/login", transport.LastRequest!.RequestUri!.AbsolutePath);
            var body = JsonDocument.Parse(transport.LastRequestBody!).RootElement;
            Assert.Equal("signer", body.GetProperty("role").GetString());
            Assert.Equal("header.payload.signature", body.GetProperty("jwt").GetString());
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    [Fact]
    public async Task Login_AppRole_SendsBothIdentifiers_AndIsMarkedSelfAuthenticated()
    {
        var (client, transport) = ClientOver(
            new VaultTransitOptions
            {
                Authentication = new VaultAuthenticationOptions
                {
                    AppRole = new AppRoleAuthenticationOptions { RoleId = "role-id", SecretId = "secret-id" },
                },
            },
            (_, _) => AuthResponse("s.approle", 1800, renewable: true));

        var lease = await client.LoginAsync(TestContext.Current.CancellationToken);

        Assert.NotNull(lease);
        Assert.Equal("s.approle", lease.Token);
        Assert.Equal("/v1/auth/approle/login", transport.LastRequest!.RequestUri!.AbsolutePath);
        var body = JsonDocument.Parse(transport.LastRequestBody!).RootElement;
        Assert.Equal("role-id", body.GetProperty("role_id").GetString());
        Assert.Equal("secret-id", body.GetProperty("secret_id").GetString());

        // The mark is what keeps the login from asking the source for the token it is about to produce.
        Assert.True(
            transport.LastRequest.Options.TryGetValue(TokenHandler.SelfAuthenticated, out var marked) && marked);
    }

    [Fact]
    public async Task Login_RefusedByVault_AnswersNull()
    {
        var (client, _) = ClientOver(
            new VaultTransitOptions
            {
                Authentication = new VaultAuthenticationOptions
                {
                    AppRole = new AppRoleAuthenticationOptions { RoleId = "r", SecretId = "wrong" },
                },
            },
            (_, _) => StubHttpMessageHandler.Json(HttpStatusCode.BadRequest, new { errors = new[] { "invalid secret id" } }));

        Assert.Null(await client.LoginAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RenewSelf_MapsTheThreeOutcomes()
    {
        var status = HttpStatusCode.OK;
        var (client, transport) = ClientOver(
            new VaultTransitOptions
            {
                Authentication = new VaultAuthenticationOptions
                {
                    AppRole = new AppRoleAuthenticationOptions { RoleId = "r", SecretId = "s" },
                },
            },
            (_, _) => status switch
            {
                HttpStatusCode.OK => AuthResponse("s.same", 600, renewable: true),
                _ => StubHttpMessageHandler.Json(status, new { errors = new[] { "some error" } }),
            });

        var renewed = await client.RenewSelfAsync("s.current", TestContext.Current.CancellationToken);
        Assert.Equal(RenewStatus.Renewed, renewed.Status);
        Assert.Equal(TimeSpan.FromMinutes(10), renewed.Lease!.LeaseDuration);
        Assert.Equal("/v1/auth/token/renew-self", transport.LastRequest!.RequestUri!.AbsolutePath);

        // The renewal carries exactly the token handed in, and is marked so the handler leaves it alone:
        // it is sent from inside the source's refresh, and an ask back would wait on that very refresh.
        Assert.Equal("s.current", transport.LastRequest.Headers.GetValues(TokenHandler.TokenHeaderName).Single());
        Assert.True(
            transport.LastRequest.Options.TryGetValue(TokenHandler.SelfAuthenticated, out var marked) && marked);

        status = HttpStatusCode.Forbidden;
        Assert.Equal(
            RenewStatus.PermissionDenied,
            (await client.RenewSelfAsync("s.current", TestContext.Current.CancellationToken)).Status);

        status = HttpStatusCode.ServiceUnavailable;
        Assert.Equal(
            RenewStatus.Failed,
            (await client.RenewSelfAsync("s.current", TestContext.Current.CancellationToken)).Status);
    }

    [Fact]
    public async Task Login_WhenVaultIsUnreachable_AnswersNullRatherThanThrowing()
    {
        var (client, _) = ClientOver(
            new VaultTransitOptions
            {
                Authentication = new VaultAuthenticationOptions
                {
                    AppRole = new AppRoleAuthenticationOptions { RoleId = "r", SecretId = "s" },
                },
            },
            (_, _) => throw new HttpRequestException("connection refused"));

        Assert.Null(await client.LoginAsync(TestContext.Current.CancellationToken));
    }
}
