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

using System;
using System.Collections.Generic;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// Pins what a host needs in order to keep its client registry in configuration: what the file says
/// is what the client gets. The configuration binder adds to a collection that already holds
/// something instead of replacing it, so a permission stored in a property initializer arrives on
/// every client whether or not the file names it - and it arrives silently, which is the part that
/// makes it worth a test.
/// </summary>
public class ClientInfoBindingTests
{
    private static IConfiguration Configuration(Dictionary<string, string?> values)
        => new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    /// <summary>
    /// A client that names one grant type gets that one grant type. With the default held in the
    /// property, the bound client also carries the authorization code grant nobody asked for.
    /// </summary>
    [Fact]
    public void Bind_GrantTypes_ReplacesRatherThanExtends()
    {
        var configuration = Configuration(new Dictionary<string, string?>
        {
            ["Clients:0:ClientId"] = "batch",
            ["Clients:0:AllowedGrantTypes:0"] = GrantTypes.RefreshToken,
        });

        var clients = configuration.GetSection("Clients").Get<ClientInfo[]>();

        Assert.NotNull(clients);
        var client = Assert.Single(clients);
        Assert.NotNull(client.AllowedGrantTypes);
        Assert.Equal([GrantTypes.RefreshToken], client.AllowedGrantTypes);
    }

    /// <summary>
    /// The same for response types, where the default is a nested collection and the appended member
    /// is a whole response type combination.
    /// </summary>
    [Fact]
    public void Bind_ResponseTypes_ReplacesRatherThanExtends()
    {
        var configuration = Configuration(new Dictionary<string, string?>
        {
            ["Clients:0:ClientId"] = "hybrid",
            ["Clients:0:AllowedResponseTypes:0:0"] = ResponseTypes.Code,
            ["Clients:0:AllowedResponseTypes:0:1"] = ResponseTypes.IdToken,
        });

        var clients = configuration.GetSection("Clients").Get<ClientInfo[]>();

        Assert.NotNull(clients);
        var client = Assert.Single(clients);
        Assert.NotNull(client.AllowedResponseTypes);
        var responseTypes = Assert.Single(client.AllowedResponseTypes);
        Assert.Equal([ResponseTypes.Code, ResponseTypes.IdToken], responseTypes);
    }

    /// <summary>
    /// A file that says nothing about grant or response types leaves the client on the library's
    /// defaults, which is what every host relied on before the registry could be bound at all.
    /// </summary>
    [Fact]
    public void Bind_WithoutGrantOrResponseTypes_KeepsLibraryDefaults()
    {
        var configuration = Configuration(new Dictionary<string, string?>
        {
            ["Clients:0:ClientId"] = "storefront",
        });

        var clients = configuration.GetSection("Clients").Get<ClientInfo[]>();

        Assert.NotNull(clients);
        var client = Assert.Single(clients);
        Assert.Equal([GrantTypes.AuthorizationCode], client.EffectiveGrantTypes);
        var responseTypes = Assert.Single(client.EffectiveResponseTypes);
        Assert.Equal([ResponseTypes.Code], responseTypes);
    }

    /// <summary>
    /// A secret is registered as a hash, and a settings file can hold one only as a single Base64
    /// string: the binder treats a byte array as a collection to fill by index, so the natural
    /// scalar has nowhere to bind without an alias for it.
    /// </summary>
    [Fact]
    public void Bind_ClientSecretHash_AcceptsBase64Scalar()
    {
        var hash = new byte[] { 0x2b, 0xb8, 0x0d, 0x53, 0x7b, 0x1d, 0xa3, 0xe3 };

        var configuration = Configuration(new Dictionary<string, string?>
        {
            ["Clients:0:ClientId"] = "storefront",
            ["Clients:0:ClientSecrets:0:Sha256HashBase64"] = Convert.ToBase64String(hash),
        });

        var clients = configuration.GetSection("Clients").Get<ClientInfo[]>();

        Assert.NotNull(clients);
        var client = Assert.Single(clients);
        Assert.NotNull(client.ClientSecrets);
        var secret = Assert.Single(client.ClientSecrets);
        Assert.Equal(hash, secret.Sha256Hash);
    }

    /// <summary>
    /// The hexadecimal notation binds the same way, because that is what a command-line digest tool
    /// prints and therefore what most registries hold. Lower case is accepted as well as upper.
    /// </summary>
    [Fact]
    public void Bind_ClientSecretHash_AcceptsHexScalar()
    {
        var hash = new byte[] { 0x2b, 0xb8, 0x0d, 0x53, 0x7b, 0x1d, 0xa3, 0xe3 };

        var configuration = Configuration(new Dictionary<string, string?>
        {
            ["Clients:0:ClientId"] = "storefront",
            ["Clients:0:ClientSecrets:0:Sha256HashHex"] = Convert.ToHexString(hash).ToLowerInvariant(),
            ["Clients:0:ClientSecrets:1:Sha512HashHex"] = Convert.ToHexString(hash),
        });

        var clients = configuration.GetSection("Clients").Get<ClientInfo[]>();

        Assert.NotNull(clients);
        var client = Assert.Single(clients);
        Assert.NotNull(client.ClientSecrets);
        Assert.Collection(
            client.ClientSecrets,
            fromLowerCase => Assert.Equal(hash, fromLowerCase.Sha256Hash),
            fromUpperCase => Assert.Equal(hash, fromUpperCase.Sha512Hash));
    }

    /// <summary>
    /// Both notations describe the same bytes, so a hash set through one member reads back through
    /// the other and neither can drift from <see cref="ClientSecret.Sha256Hash"/> itself.
    /// </summary>
    [Fact]
    public void SecretHashNotations_AgreeWithEachOther()
    {
        var hash = new byte[] { 0x2b, 0xb8, 0x0d, 0x53 };

        var secret = new ClientSecret { Sha256HashBase64 = Convert.ToBase64String(hash) };

        Assert.Equal(hash, secret.Sha256Hash);
        Assert.Equal(Convert.ToHexString(hash), secret.Sha256HashHex);
    }

    /// <summary>
    /// Hosts that build clients in code keep the shape they had: an unset grant list still behaves
    /// as the authorization code grant, and nothing about the positional identifier changes.
    /// </summary>
    [Fact]
    public void ConstructedInCode_KeepsTheDefaultsItAlwaysHad()
    {
        var client = new ClientInfo("storefront");

        Assert.Equal("storefront", client.ClientId);
        Assert.Equal([GrantTypes.AuthorizationCode], client.EffectiveGrantTypes);
    }
}
