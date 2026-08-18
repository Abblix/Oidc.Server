// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Collections.Generic;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// Verifies that <see cref="ClientSecretsOptionsValidator"/> refuses a client that cannot
/// authenticate with the secret it appears to carry. The case worth the test is the quiet one: the
/// configuration binder discards an element whose binding threw, so a hash a settings file spells
/// wrongly leaves the client with no secret rather than a bad one, and every request that client
/// ever makes is refused with nothing said about why.
/// </summary>
public class ClientSecretsOptionsValidatorTests
{
    private readonly ClientSecretsOptionsValidator _validator = new();

    private static byte[] Sha256Sized() => new byte[256 / 8];

    /// <summary>
    /// A client that authenticates by shared secret and has none cannot ever succeed, so the host
    /// hears about it while it is still starting.
    /// </summary>
    [Fact]
    public void Validate_SecretAuthenticationWithoutSecrets_Fails()
    {
        var options = new OidcOptions
        {
            Clients =
            [
                new ClientInfo("storefront")
                {
                    TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
                },
            ],
        };

        var result = _validator.Validate(null, options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, failure => failure.Contains("storefront"));
    }

    /// <summary>
    /// A public client has no secret by definition, so the same shape must pass.
    /// </summary>
    [Fact]
    public void Validate_PublicClientWithoutSecrets_Succeeds()
    {
        var options = new OidcOptions
        {
            Clients =
            [
                new ClientInfo("mobile") { TokenEndpointAuthMethod = ClientAuthenticationMethods.None },
            ],
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }

    /// <summary>
    /// A digest pasted in the wrong notation decodes without complaint and to the wrong length, which
    /// is the only trace it leaves before the client starts failing to authenticate.
    /// </summary>
    [Fact]
    public void Validate_HashOfWrongLength_Fails()
    {
        var options = new OidcOptions
        {
            Clients =
            [
                new ClientInfo("storefront")
                {
                    TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
                    ClientSecrets = [new ClientSecret { Sha256Hash = new byte[20] }],
                },
            ],
        };

        var result = _validator.Validate(null, options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, failure => failure.Contains("20 bytes"));
    }

    /// <summary>
    /// A correctly sized hash on a client that uses it passes, which is the control that keeps the
    /// two checks above meaningful.
    /// </summary>
    [Fact]
    public void Validate_WellFormedSecret_Succeeds()
    {
        var options = new OidcOptions
        {
            Clients =
            [
                new ClientInfo("storefront")
                {
                    TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
                    ClientSecrets = [new ClientSecret { Sha256Hash = Sha256Sized() }],
                },
            ],
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }

    /// <summary>
    /// The whole chain, from the settings file to the startup refusal: a hash the binder cannot read
    /// leaves the client with no secrets at all, and that is what the validator is here to notice.
    /// </summary>
    [Fact]
    public void Validate_ClientWhoseHashTheBinderCouldNotRead_Fails()
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

        var result = _validator.Validate(null, new OidcOptions { Clients = clients });

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, failure => failure.Contains("Base64 or hexadecimal"));
    }

    /// <summary>
    /// client_secret_jwt signs with the raw secret as the HMAC key, and a hash cannot recover it, so
    /// a client whose secrets are all hashes can never authenticate. Hashing the secret is exactly
    /// what a careful operator does for the other secret methods, which is what makes this mistake
    /// likely, and the authenticator skips such a secret with a debug log nobody reads.
    /// </summary>
    [Fact]
    public void Validate_ClientSecretJwtWithHashOnlySecrets_Fails()
    {
        var options = new OidcOptions
        {
            Clients =
            [
                new ClientInfo("storefront")
                {
                    TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
                    ClientSecrets = [new ClientSecret { Sha256Hash = Sha256Sized() }],
                },
            ],
        };

        var result = _validator.Validate(null, options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, failure => failure.Contains("HMAC"));
    }

    /// <summary>
    /// The same client with the raw value present is fine, which keeps the check above about the
    /// form of the secret rather than its presence.
    /// </summary>
    [Fact]
    public void Validate_ClientSecretJwtWithRawValue_Succeeds()
    {
        var options = new OidcOptions
        {
            Clients =
            [
                new ClientInfo("storefront")
                {
                    TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
                    ClientSecrets = [new ClientSecret { Value = new string('s', 32) }],
                },
            ],
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }

    /// <summary>
    /// The mirror image: client_secret_basic and client_secret_post compare the presented secret
    /// against a stored hash and never read the raw value, so a client whose only secret is a raw
    /// value can never authenticate either.
    /// </summary>
    [Fact]
    public void Validate_HashComparedMethodWithRawValueOnlySecret_Fails()
    {
        var options = new OidcOptions
        {
            Clients =
            [
                new ClientInfo("storefront")
                {
                    TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretBasic,
                    ClientSecrets = [new ClientSecret { Value = new string('s', 32) }],
                },
            ],
        };

        var result = _validator.Validate(null, options);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Failures!, failure => failure.Contains(nameof(ClientSecret.Sha256HashBase64)));
    }
}
