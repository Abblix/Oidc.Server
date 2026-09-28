// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Reflection;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Validation;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.Mvc;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token.Validation;

/// <summary>
/// The order of the token endpoint's validators as the library composes them.
/// </summary>
/// <remarks>
/// A device code and a backchannel authentication request are spent while <see cref="AuthorizationGrantValidator"/>
/// resolves the grant, so every refusal a client is expected to recover from by retrying has to come before it.
/// The DPoP nonce challenge is one: RFC 9449 section 8 answers it with the same request and a fresh proof, and
/// behind the spend that retry finds the grant gone.
/// </remarks>
public class TokenValidatorOrderTests
{
    [Fact]
    public void TheDPoPProofIsJudgedBeforeTheGrantIsResolved_AndItsBindingAfter()
    {
        var validators = ExtractComposedValidators(
            BuildProvider().GetRequiredService<ITokenContextValidator>());

        var proof = Array.FindIndex(validators, v => v is DPoPTokenEndpointValidator);
        var grant = Array.FindIndex(validators, v => v is AuthorizationGrantValidator);
        var binding = Array.FindIndex(validators, v => v is DPoPBindingValidator);

        Assert.True(proof >= 0 && grant >= 0 && binding >= 0, "each of the three is composed");
        Assert.True(proof < grant, "the proof is judged before the grant is resolved");
        Assert.True(grant < binding, "the binding is compared after the grant is resolved");
    }

    private static ITokenContextValidator[] ExtractComposedValidators(ITokenContextValidator composite)
    {
        // Compose() removes the individual descriptors and captures them inside the composite's
        // constructor-injected array, so the pipeline as composed is read back from that array, located by
        // its type rather than by the compiler-generated field name.
        var field = composite.GetType()
            .GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public)
            .Single(f => f.FieldType == typeof(ITokenContextValidator[]));

        return (ITokenContextValidator[])field.GetValue(composite)!;
    }

    private static IServiceProvider BuildProvider()
    {
        var services = new ServiceCollection();

        // Host-level prerequisites every real ASP.NET host registers.
        services.AddDistributedMemoryCache();
        services.AddMemoryCache();
        services.AddSingleton(Mock.Of<IUserCredentialsAuthenticator>());
        services.AddSingleton(Mock.Of<IUserInfoProvider>());

        services.AddOidcServices(options =>
        {
            options.Issuer = TestConstants.DefaultIssuer.OriginalString;
            options.SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)];
            options.RequireInitialAccessToken = false;
        });

        return services.BuildServiceProvider();
    }
}
