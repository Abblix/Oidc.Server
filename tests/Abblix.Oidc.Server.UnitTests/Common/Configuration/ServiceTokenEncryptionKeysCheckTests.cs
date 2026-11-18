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
using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// Verifies that <see cref="ServiceTokenEncryptionKeysCheck"/> refuses a tenant with no key to encrypt a service
/// token the server's settings ask to encrypt, and leaves alone every tenant whose key exists or may exist.
/// </summary>
public class ServiceTokenEncryptionKeysCheckTests
{
    private static List<TenantRefusal> Check(
        OidcOptions options,
        JsonWebKey[]? encryptionKeys = null,
        IKeyCustodian? custodian = null)
        => new ServiceTokenEncryptionKeysCheck(custodian).Check(
            [
                new TenantDefinition
                {
                    Id = "acme",
                    Issuer = new Uri("https://auth.example.com"),
                    EncryptionKeys = encryptionKeys ?? [],
                },
            ],
            options).ToList();

    /// <summary>
    /// A host that requires encryption while no key can serve it is refused at startup, naming the tenant, the
    /// setting and the way out. Left to run, it would reach issuance and produce a token whose confidentiality
    /// the configuration promises and the output does not carry.
    /// </summary>
    [Fact]
    public void Check_EncryptRequiredWithoutAnyKey_Refuses()
    {
        var options = new OidcOptions();
        options.ServiceTokens.AccessToken.Encrypt = true;

        var refusal = Assert.Single(Check(options));

        Assert.Equal("acme", Assert.Single(refusal.TenantIds));
        Assert.Contains("AccessToken.Encrypt is true", refusal.Message);
    }

    /// <summary>
    /// The same requirement passes once the tenant declares a key, which is the whole condition being checked.
    /// </summary>
    [Fact]
    public void Check_EncryptRequiredWithDeclaredKey_Passes()
    {
        var options = new OidcOptions();
        options.ServiceTokens.AccessToken.Encrypt = true;

        Assert.Empty(Check(options, encryptionKeys: [new RsaJsonWebKey { KeyId = "enc-key" }]));
    }

    /// <summary>
    /// With an external custodian registered the keys live outside the tenant's settings, so an empty
    /// <see cref="TenantDefinition.EncryptionKeys"/> says nothing about whether a key exists. Refusing here would
    /// reject startup for exactly the deployments that keep their keys in a Vault or Key Vault backend.
    /// </summary>
    [Fact]
    public void Check_EncryptRequiredWithCustodian_Passes()
    {
        var options = new OidcOptions();
        options.ServiceTokens.AccessToken.Encrypt = true;

        Assert.Empty(Check(options, custodian: new Mock<IKeyCustodian>(MockBehavior.Strict).Object));
    }

    /// <summary>
    /// A host that never stated a decision keeps starting with no keys declared, which is what separates
    /// "asked to encrypt" from "did not object" and why the setting is nullable. The shipped default is this
    /// state, so refusing it would break every deployment that does not use encryption at all.
    /// </summary>
    [Fact]
    public void Check_EncryptUnstatedWithoutAnyKey_Passes()
    {
        var options = new OidcOptions();

        Assert.Null(options.ServiceTokens.AccessToken.Encrypt);
        Assert.Empty(Check(options));
    }
}
