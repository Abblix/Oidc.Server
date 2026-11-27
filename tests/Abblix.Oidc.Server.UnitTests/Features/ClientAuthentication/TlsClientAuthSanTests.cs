// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Abblix.Tests.Shared;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// The subject alternative names a tls_client_auth client registers (RFC 8705 section 2.1.2), compared with the
/// certificate's entries.
/// </summary>
public class TlsClientAuthSanTests
{
    private const string ClientId = "san-client";

    private static readonly TestCertificateAuthority Authority = TestCertificateAuthority.Create("CN=SAN Test Root CA");

    private static readonly TenantDefinition Tenant = new()
    {
        Id = SingleIssuer.Tenant.Id,
        Issuer = SingleIssuer.Tenant.Issuer,
        TlsClientAuthCertificateAuthorities = [Authority.RootEncoded],
    };

    private static async Task<bool> AuthenticatesAsync(TlsClientAuthOptions registered, Action<SubjectAlternativeNameBuilder> san)
    {
        var client = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuth = registered,
        };
        var clients = new Mock<IClientInfoProvider>();
        clients.Setup(x => x.FindClientAsync(TestTenant.Matched, ClientId)).ReturnsAsync(client);

        var builder = new SubjectAlternativeNameBuilder();
        san(builder);
        var extension = builder.Build();
        using var certificate = Authority.Issue("CN=san-client", request => request.CertificateExtensions.Add(extension));

        var result = await new TlsMetadataClientAuthenticator(
                NullLogger<TlsMetadataClientAuthenticator>.Instance, TimeProvider.System)
            .TryAuthenticateClientAsync(
                Tenant,
                new ClientRequest { ClientId = ClientId, ClientCertificate = certificate },
                clients.Object);
        return result.TryGetSuccess(out _);
    }

    /// <summary>
    /// A URI is compared as a string (RFC 3986 section 6.2.1): one differing in its fragment or its user information
    /// is another URI.
    /// </summary>
    [Theory]
    [InlineData("https://client.example.com/id", true)]
    [InlineData("https://client.example.com/id#other", false)]
    [InlineData("https://someone@client.example.com/id", false)]
    public async Task AUriIsComparedAsWritten(string registered, bool authenticates)
    {
        Assert.Equal(authenticates, await AuthenticatesAsync(
            new TlsClientAuthOptions { SanUris = [new Uri(registered)] },
            san => san.AddUri(new Uri("https://client.example.com/id"))));
    }

    /// <summary>
    /// RFC 8705 section 2.1.2: the IP address comparison "is to be done in binary format", so any spelling of the
    /// certificate's address matches it, and another address does not.
    /// </summary>
    [Theory]
    [InlineData("2001:db8::1", true)]
    [InlineData("2001:DB8::1", true)]
    [InlineData("2001:0db8:0:0:0:0:0:1", true)]
    [InlineData("2001:db8::2", false)]
    [InlineData("not an address", false)]
    public async Task AnIpAddressIsComparedInBinary(string registered, bool authenticates)
    {
        Assert.Equal(authenticates, await AuthenticatesAsync(
            new TlsClientAuthOptions { SanIps = [registered] },
            san => san.AddIpAddress(IPAddress.Parse("2001:db8::1"))));
    }
}
