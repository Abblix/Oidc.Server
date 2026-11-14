// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Linq;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// Verifies that <see cref="ClientSecretsCheck"/> refuses a tenant's client that cannot
/// authenticate with the secret it appears to carry. The case worth the test is the quiet one: the
/// configuration binder discards an element whose binding threw, so a hash a settings file spells
/// wrongly leaves the client with no secret rather than a bad one, and every request that client
/// ever makes is refused with nothing said about why.
/// </summary>
public class ClientSecretsCheckTests
{
    private readonly ClientSecretsCheck _check = new();

    private static byte[] Sha256Sized() => new byte[256 / 8];

    private static TenantDefinition TenantWith(params ClientInfo[] clients) => new()
    {
        Id = "acme",
        Issuer = new Uri("https://auth.example.com"),
        Clients = clients,
    };

    private List<TenantRefusal> RefusalsOf(params ClientInfo[] clients)
        => _check.Check([TenantWith(clients)], new OidcOptions()).ToList();

    /// <summary>
    /// A client that authenticates by shared secret and has none cannot ever succeed, so the host
    /// hears about it while it is still starting, and the refusal names the tenant it belongs to.
    /// </summary>
    [Fact]
    public void Check_SecretAuthenticationWithoutSecrets_Refuses()
    {
        var refusals = RefusalsOf(
            new ClientInfo("storefront") { TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost });

        var refusal = Assert.Single(refusals);
        Assert.Equal("acme", Assert.Single(refusal.TenantIds));
        Assert.Contains("storefront", refusal.Message);
    }

    /// <summary>
    /// A public client has no secret by definition, so the same shape must pass.
    /// </summary>
    [Fact]
    public void Check_PublicClientWithoutSecrets_Passes()
    {
        var refusals = RefusalsOf(
            new ClientInfo("mobile") { TokenEndpointAuthMethod = ClientAuthenticationMethods.None });

        Assert.Empty(refusals);
    }

    /// <summary>
    /// A digest pasted in the wrong notation decodes without complaint and to the wrong length, which
    /// is the only trace it leaves before the client starts failing to authenticate.
    /// </summary>
    [Fact]
    public void Check_HashOfWrongLength_Refuses()
    {
        var refusals = RefusalsOf(
            new ClientInfo("storefront")
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
                ClientSecrets = [new ClientSecret { Sha256Hash = new byte[20] }],
            });

        Assert.Contains(refusals, refusal => refusal.Message.Contains("20 bytes"));
    }

    /// <summary>
    /// A correctly sized hash on a client that uses it passes, which is the control that keeps the
    /// two checks above meaningful.
    /// </summary>
    [Fact]
    public void Check_WellFormedSecret_Passes()
    {
        var refusals = RefusalsOf(
            new ClientInfo("storefront")
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
                ClientSecrets = [new ClientSecret { Sha256Hash = Sha256Sized() }],
            });

        Assert.Empty(refusals);
    }

    /// <summary>
    /// The whole chain, from the settings file to the startup refusal: a hash the binder cannot read
    /// leaves the client with no secrets at all, and that is what the check is here to notice.
    /// </summary>
    [Fact]
    public void Check_ClientWhoseHashTheBinderCouldNotRead_Refuses()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Clients:0:ClientId"] = "storefront",
                ["Clients:0:TokenEndpointAuthMethod"] = ClientAuthenticationMethods.ClientSecretPost,
                // A digest copied with the spaces a spreadsheet adds and a digest tool does not print.
                ["Clients:0:ClientSecrets:0:Sha256HashHex"] = "5e88 4898 da28 0471",
            })
            .Build();

        var clients = configuration.GetSection("Clients").Get<ClientInfo[]>();

        Assert.NotNull(clients);
        var client = Assert.Single(clients);

        // The binder builds the collection and then drops the element whose binding threw, so the
        // client arrives with an empty secret list rather than with a bad secret or an error.
        Assert.NotNull(client.ClientSecrets);
        Assert.Empty(client.ClientSecrets);

        var refusals = RefusalsOf(clients);

        Assert.Contains(refusals, refusal => refusal.Message.Contains("Base64 or hexadecimal"));
    }

    /// <summary>
    /// client_secret_jwt signs with the raw secret as the HMAC key, and a hash cannot recover it, so
    /// a client whose secrets are all hashes can never authenticate. Hashing the secret is exactly
    /// what a careful operator does for the other secret methods, which is what makes this mistake
    /// likely, and the authenticator skips such a secret with a debug log nobody reads.
    /// </summary>
    [Fact]
    public void Check_ClientSecretJwtWithHashOnlySecrets_Refuses()
    {
        var refusals = RefusalsOf(
            new ClientInfo("storefront")
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
                ClientSecrets = [new ClientSecret { Sha256Hash = Sha256Sized() }],
            });

        Assert.Contains(refusals, refusal => refusal.Message.Contains("HMAC"));
    }

    /// <summary>
    /// The same client with the raw value present is fine, which keeps the check above about the
    /// form of the secret rather than its presence.
    /// </summary>
    [Fact]
    public void Check_ClientSecretJwtWithRawValue_Passes()
    {
        var refusals = RefusalsOf(
            new ClientInfo("storefront")
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
                ClientSecrets = [new ClientSecret { Value = new string('s', 32) }],
            });

        Assert.Empty(refusals);
    }

    /// <summary>
    /// The mirror image: client_secret_basic and client_secret_post compare the presented secret
    /// against a stored hash and never read the raw value, so a client whose only secret is a raw
    /// value can never authenticate either.
    /// </summary>
    [Fact]
    public void Check_HashComparedMethodWithRawValueOnlySecret_Refuses()
    {
        var refusals = RefusalsOf(
            new ClientInfo("storefront")
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
                ClientSecrets = [new ClientSecret { Value = new string('s', 32) }],
            });

        Assert.Contains(refusals, refusal => refusal.Message.Contains(nameof(ClientSecret.Sha256HashBase64)));
    }
}
