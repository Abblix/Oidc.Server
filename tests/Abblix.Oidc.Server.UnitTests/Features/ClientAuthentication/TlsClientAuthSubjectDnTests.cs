// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Formats.Asn1;
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
/// RFC 8705 section 2.1: the certificate's subject is compared with the registered DN by "a predictable treatment of
/// DN values, such as the distinguishedNameMatch rule from [RFC4517]", whose values RFC 5280 section 7.1 compares
/// after the RFC 4518 string preparation.
/// </summary>
public class TlsClientAuthSubjectDnTests
{
    private const string ClientId = "dn-client";

    private static readonly TestCertificateAuthority Authority = TestCertificateAuthority.Create("CN=DN Test Root CA");

    private static TenantDefinition Tenant => new()
    {
        Id = SingleIssuer.Tenant.Id,
        Issuer = SingleIssuer.Tenant.Issuer,
        TlsClientAuthCertificateAuthorities = [Authority.RootEncoded],
    };

    private static async Task<bool> AuthenticatesAsync(string registeredDn, X500DistinguishedName subject)
    {
        var client = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuth = new TlsClientAuthOptions { SubjectDn = registeredDn },
        };
        var clients = new Mock<IClientInfoProvider>();
        clients.Setup(x => x.FindClientAsync(TestTenant.Matched, ClientId)).ReturnsAsync(client);

        using var certificate = Authority.Issue(subject);
        var result = await new TlsMetadataClientAuthenticator(
                NullLogger<TlsMetadataClientAuthenticator>.Instance, TimeProvider.System)
            .TryAuthenticateClientAsync(
                Tenant,
                new ClientRequest { ClientId = ClientId, ClientCertificate = certificate },
                clients.Object);
        return result.TryGetSuccess(out _);
    }

    /// <summary>
    /// The subject a certificate authority writes, with UTF8String values as OpenSSL does by default, encoded C, then
    /// O, then CN: the builder encodes the name it is given most specific first, as RFC 4514 writes it.
    /// </summary>
    private static X500DistinguishedName Utf8Subject()
    {
        var builder = new X500DistinguishedNameBuilder();
        builder.AddCommonName("client");
        builder.AddOrganizationName("Example Org");
        builder.AddCountryOrRegion("US");
        return builder.Build();
    }

    /// <summary>
    /// A certificate whose subject values are UTF8String matches the DN registered as a string, which parses to
    /// PrintableString values: the two encode one name.
    /// </summary>
    [Fact]
    public async Task Utf8SubjectMatchesTheRegisteredString()
    {
        Assert.True(await AuthenticatesAsync("CN=client, O=Example Org, C=US", Utf8Subject()));
    }

    /// <summary>
    /// RFC 4518 caseIgnoreMatch with insignificant space handling: case and runs of spaces do not tell two values
    /// apart.
    /// </summary>
    [Fact]
    public async Task CaseAndInsignificantSpacesDoNotMatter()
    {
        Assert.True(await AuthenticatesAsync("CN=CLIENT, O=example   org, C=us", Utf8Subject()));
    }

    /// <summary>
    /// Another value, another order of the RDNs or another number of them is another name.
    /// </summary>
    [Theory]
    [InlineData("CN=other, O=Example Org, C=US")]
    [InlineData("C=US, O=Example Org, CN=client")]
    [InlineData("CN=client, O=Example Org")]
    [InlineData("O=Example Org, C=US")]
    [InlineData("CN=client, O=Example Org, C=US, L=Somewhere")]
    [InlineData("CN=client, OU=Example Org, C=US")]
    public async Task AnotherNameDoesNotMatch(string registeredDn)
    {
        Assert.False(await AuthenticatesAsync(registeredDn, Utf8Subject()));
    }

    /// <summary>
    /// RFC 4517 section 4.2.15: an RDN is the same as another only when it holds "the same number of attribute value
    /// assertions", so an RDN holding the registered common name beside another value is another RDN.
    /// </summary>
    [Fact]
    public async Task MultiValuedRdnDoesNotMatchOneOfItsValues()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            WriteRdn(writer, (CountryOid, "US"));
            WriteRdn(writer, (OrganizationOid, "Example Org"));
            WriteRdn(writer, (CommonNameOid, "client"), (UserIdOid, "42"));
        }

        Assert.False(await AuthenticatesAsync(
            "CN=client, O=Example Org, C=US", new X500DistinguishedName(writer.Encode())));
    }

    private const string CountryOid = "2.5.4.6";
    private const string OrganizationOid = "2.5.4.10";
    private const string CommonNameOid = "2.5.4.3";
    private const string UserIdOid = "0.9.2342.19200300.100.1.1";

    private static void WriteRdn(AsnWriter writer, params (string Oid, string Value)[] attributes)
    {
        using (writer.PushSetOf())
        {
            foreach (var (oid, value) in attributes)
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(oid);
                    writer.WriteCharacterString(UniversalTagNumber.UTF8String, value);
                }
            }
        }
    }
}
