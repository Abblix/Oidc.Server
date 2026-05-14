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
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// Verifies that <see cref="ClientJwksConfigurationExtensions"/> populates
/// <c>ClientInfo.Jwks</c> from configuration sections the standard binder leaves
/// unbound, dispatches the correct concrete <c>JsonWebKey</c> subtype by <c>kty</c>,
/// and stays a no-op when the host has already supplied <c>Jwks</c>.
/// </summary>
public class ClientJwksConfigurationExtensionsTests
{
    [Fact]
    public void AssignsJwks_WhenSectionPresentAndJwksNull()
    {
        const string json = """
            {
              "Clients": [
                {
                  "ClientId": "test-client",
                  "Jwks": {
                    "Keys": [
                      {
                        "kty": "RSA",
                        "kid": "k1",
                        "use": "sig",
                        "alg": "RS256",
                        "n": "AQAB",
                        "e": "AQAB"
                      }
                    ]
                  }
                }
              ]
            }
            """;
        var clients = ApplyConfig(json, new ClientInfo("test-client"));

        var jwks = clients.Single().Jwks;
        Assert.NotNull(jwks);
        var key = Assert.IsType<RsaJsonWebKey>(jwks.Keys.Single());
        Assert.Equal("k1", key.KeyId);
        Assert.Equal("sig", key.Usage);
        Assert.Equal("RS256", key.Algorithm);
    }

    [Fact]
    public void SkipsAssignment_WhenJwksAlreadyPopulated()
    {
        var existing = new JsonWebKeySet([new RsaJsonWebKey { KeyId = "preset" }]);
        const string json = """
            {
              "Clients": [
                {
                  "ClientId": "test-client",
                  "Jwks": {
                    "Keys": [
                      { "kty": "RSA", "kid": "would-be-overwritten", "n": "AQAB", "e": "AQAB" }
                    ]
                  }
                }
              ]
            }
            """;
        var clients = ApplyConfig(json, new ClientInfo("test-client") { Jwks = existing });

        Assert.Same(existing, clients.Single().Jwks);
        Assert.Equal("preset", clients.Single().Jwks!.Keys.Single().KeyId);
    }

    [Fact]
    public void SkipsAssignment_WhenClientIdInConfigHasNoMatchInOptions()
    {
        const string json = """
            {
              "Clients": [
                {
                  "ClientId": "config-only-client",
                  "Jwks": {
                    "Keys": [{ "kty": "RSA", "kid": "k1", "n": "AQAB", "e": "AQAB" }]
                  }
                }
              ]
            }
            """;
        var clients = ApplyConfig(json, new ClientInfo("different-client"));

        Assert.Null(clients.Single().Jwks);
    }

    [Fact]
    public void LeavesJwksNull_WhenNoJwksSection()
    {
        const string json = """
            {
              "Clients": [
                { "ClientId": "test-client", "TokenEndpointAuthMethod": "none" }
              ]
            }
            """;
        var clients = ApplyConfig(json, new ClientInfo("test-client"));

        Assert.Null(clients.Single().Jwks);
    }

    [Fact]
    public void DispatchesByKty_ResolvesConcreteSubtypes()
    {
        const string json = """
            {
              "Clients": [
                {
                  "ClientId": "rsa-client",
                  "Jwks": {
                    "Keys": [{ "kty": "RSA", "kid": "r", "n": "AQAB", "e": "AQAB" }]
                  }
                },
                {
                  "ClientId": "ec-client",
                  "Jwks": {
                    "Keys": [
                      { "kty": "EC", "kid": "e", "crv": "P-256", "x": "AQAB", "y": "AQAB" }
                    ]
                  }
                }
              ]
            }
            """;
        var clients = ApplyConfig(json,
            new ClientInfo("rsa-client"),
            new ClientInfo("ec-client"));

        var rsa = clients.First(c => c.ClientId == "rsa-client").Jwks!.Keys.Single();
        var ec = clients.First(c => c.ClientId == "ec-client").Jwks!.Keys.Single();
        Assert.IsType<RsaJsonWebKey>(rsa);
        Assert.IsType<EllipticCurveJsonWebKey>(ec);
    }

    [Fact]
    public void AcceptsPascalCasePropertyNames_AsWellAsLowercase()
    {
        const string json = """
            {
              "Clients": [
                {
                  "ClientId": "pascal-client",
                  "Jwks": {
                    "Keys": [
                      {
                        "Kty": "RSA",
                        "Kid": "pk",
                        "Use": "sig",
                        "Alg": "RS256",
                        "N": "AQAB",
                        "E": "AQAB"
                      }
                    ]
                  }
                }
              ]
            }
            """;
        var clients = ApplyConfig(json, new ClientInfo("pascal-client"));

        var key = Assert.IsType<RsaJsonWebKey>(clients.Single().Jwks!.Keys.Single());
        Assert.Equal("pk", key.KeyId);
    }

    [Fact]
    public void Throws_WhenJwksKtyIsUnknown()
    {
        const string json = """
            {
              "Clients": [
                {
                  "ClientId": "broken",
                  "Jwks": { "Keys": [{ "kty": "UNKNOWN_TYPE" }] }
                }
              ]
            }
            """;
        Assert.Throws<InvalidOperationException>(() => ApplyConfig(json, new ClientInfo("broken")));
    }

    [Fact]
    public void Throws_WhenJwksKtyIsMissing()
    {
        const string json = """
            {
              "Clients": [
                {
                  "ClientId": "missing-kty",
                  "Jwks": { "Keys": [{ "kid": "no-kty" }] }
                }
              ]
            }
            """;
        Assert.Throws<InvalidOperationException>(() => ApplyConfig(json, new ClientInfo("missing-kty")));
    }

    [Fact]
    public void LoadsFromAppsettingsJsonFile()
    {
        var path = Path.Combine(Path.GetTempPath(), $"appsettings-{Guid.NewGuid():N}.json");
        try
        {
            File.WriteAllText(path, """
                {
                  "Clients": [
                    {
                      "ClientId": "from-file-client",
                      "TokenEndpointAuthMethod": "private_key_jwt",
                      "Jwks": {
                        "Keys": [
                          {
                            "kty": "RSA",
                            "kid": "file-k1",
                            "use": "sig",
                            "alg": "PS256",
                            "n": "AQAB",
                            "e": "AQAB"
                          }
                        ]
                      }
                    }
                  ]
                }
                """);

            var config = new ConfigurationBuilder()
                .AddJsonFile(path, optional: false)
                .Build();

            var clients = new[] { new ClientInfo("from-file-client") }
                .WithJwksFromConfiguration(config.GetSection("Clients"));

            var jwks = clients.Single().Jwks;
            Assert.NotNull(jwks);
            var key = Assert.IsType<RsaJsonWebKey>(jwks.Keys.Single());
            Assert.Equal("file-k1", key.KeyId);
            Assert.Equal("PS256", key.Algorithm);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    /// <summary>
    /// Compile-time guard: a host that wraps <see cref="ClientInfo"/> in its own derived
    /// record (with extra metadata like logos, external provider mappings, …) must be able
    /// to assign the extension's return value back to its strongly-typed <c>Clients</c>
    /// array without a cast. Regression for the type-preserving generic signature.
    /// </summary>
    public sealed record DerivedClientInfo(string ClientId) : ClientInfo(ClientId)
    {
        public string? Label { get; init; }
    }

    [Fact]
    public void Generic_PreservesDerivedArrayType_AcrossCallsite()
    {
        const string json = """
            {
              "Clients": [
                {
                  "ClientId": "derived-client",
                  "Jwks": {
                    "Keys": [{ "kty": "RSA", "kid": "dk", "n": "AQAB", "e": "AQAB" }]
                  }
                }
              ]
            }
            """;
        var config = new ConfigurationBuilder()
            .AddJsonStream(new MemoryStream(Encoding.UTF8.GetBytes(json)))
            .Build();

        DerivedClientInfo[] source = [new DerivedClientInfo("derived-client") { Label = "preserved" }];

        // Critical: return type must be DerivedClientInfo[], not ClientInfo[]
        DerivedClientInfo[] result = source.WithJwksFromConfiguration(config.GetSection("Clients"));

        var derived = Assert.Single(result);
        Assert.Equal("preserved", derived.Label);
        Assert.NotNull(derived.Jwks);
        Assert.Equal("dk", derived.Jwks.Keys.Single().KeyId);
    }

    [Fact]
    public void OidcOptionsWrapper_DelegatesToClientArrayExtension()
    {
        const string json = """
            {
              "Clients": [
                {
                  "ClientId": "wrap",
                  "Jwks": {
                    "Keys": [{ "kty": "RSA", "kid": "w", "n": "AQAB", "e": "AQAB" }]
                  }
                }
              ]
            }
            """;
        var config = new ConfigurationBuilder()
            .AddJsonStream(new MemoryStream(Encoding.UTF8.GetBytes(json)))
            .Build();

        var opts = new OidcOptions { Clients = [new ClientInfo("wrap")] };
        opts.AddClientJwksFromConfiguration(config.GetSection("Clients"));

        var key = Assert.IsType<RsaJsonWebKey>(opts.Clients.First().Jwks!.Keys.Single());
        Assert.Equal("w", key.KeyId);
    }

    /// <summary>
    /// Regression coverage for the .NET 10 binder edge case. On .NET 10 the standard
    /// configuration binder pre-creates a non-null <see cref="JsonWebKeySet"/> for the
    /// <c>Jwks</c> property with an empty <c>Keys</c> array (it constructs the wrapper but
    /// cannot construct the polymorphic <see cref="JsonWebKey"/> entries). The previous
    /// <c>Jwks is not null</c> guard then skipped the bind-from-config work and clients
    /// ended up with zero signing keys at runtime, producing
    /// <c>"no signing keys configured for issuer"</c> for every <c>private_key_jwt</c>
    /// client_assertion. Caught against AuthSvc 2026-05-14 while running the OIDF
    /// Conformance FAPI 2.0 PAR test against prod (auth-service v365).
    /// </summary>
    public sealed class SettingsLike
    {
        public ClientInfo[] Clients { get; set; } = [];
    }

    [Fact]
    public void EndToEndConfigGet_NetTenBinder_PrePopulatesEmptyJwks_BindOverwrites()
    {
        const string json = """
            {
              "Clients": [
                {
                  "ClientId": "oidf-fapi2-test",
                  "TokenEndpointAuthMethod": "private_key_jwt",
                  "RequireDPoP": true,
                  "Jwks": {
                    "keys": [
                      {
                        "kty": "RSA",
                        "kid": "abblix-fapi2-client1-3c896038",
                        "use": "sig",
                        "alg": "PS256",
                        "n": "ulOIreKtMsORZrW2pI1obZ67NEV649xerW6Q9LNzOgQ0RUGrpNBub-AA2GqPWH0EgZ13BEXIHviqlk3BD94335ULNWiTbEL_vQso0xDmSBaRoRd5flEsjjcnAVt7bvkK_pLvpZgDZg869e6hG1zKuHD5Oa4CBfwg1F6Zy4uT_SwiKgEyAzOeGjZVO5Zcg17iIJll4tRB0D4pXNNrL9pW1Aih7EfKZZwffuPHMjvo57R4vyHglwuoA8Mcrf7oeuQIVVjOjZF-sFD-KVdNXuFPeWKjuIpu4_nRBLebcn6KHU276kXZtKYxrk-SpKoej1BYlvuKrWLwOvaFpH4fc9DHHQ",
                        "e": "AQAB"
                      }
                    ]
                  }
                }
              ]
            }
            """;

        var config = new ConfigurationBuilder()
            .AddJsonStream(new MemoryStream(Encoding.UTF8.GetBytes(json)))
            .Build();

        // Step 1: same as Program.cs line 98 — configuration.Get<Settings>()
        var settings = config.Get<SettingsLike>();
        Assert.NotNull(settings);
        Assert.Single(settings.Clients);
        Assert.Equal("oidf-fapi2-test", settings.Clients[0].ClientId);

        // CRITICAL — on .NET 10, the binder DOES populate Jwks natively, BUT with what?
        // Inspect raw state.
        // After Get<T>(), the .NET 10 binder pre-creates a non-null JsonWebKeySet with
        // an empty Keys array because it cannot construct the polymorphic JsonWebKey
        // entries. WithJwksFromConfiguration must treat this as "needs binding".
        Assert.NotNull(settings.Clients[0].Jwks);
        Assert.Empty(settings.Clients[0].Jwks!.Keys);

        // Step 2: same as Program.cs line 99
        settings.Clients = settings.Clients.WithJwksFromConfiguration(config.GetSection("Clients"));

        // After WithJwksFromConfiguration, Keys must be populated from the JSON.
        var jwksAfter = settings.Clients[0].Jwks;
        Assert.NotNull(jwksAfter);
        var key = Assert.IsType<RsaJsonWebKey>(jwksAfter.Keys.Single());
        Assert.Equal("abblix-fapi2-client1-3c896038", key.KeyId);
        Assert.Equal("PS256", key.Algorithm);
        Assert.Equal("sig", key.Usage);
        Assert.NotNull(key.Modulus);
        Assert.NotEmpty(key.Modulus);
    }

    /// <summary>
    /// Reproduces the AuthSvc prod configuration shape: top-level "Clients" array, lowercase
    /// "keys" inside "Jwks", actual base64url RSA modulus from oidf-fapi2-test. Sanity-check that
    /// the binding produces a non-empty Jwks for this exact layout before chasing config issues elsewhere.
    /// </summary>
    [Fact]
    public void AuthSvcShape_BindsLowercaseKeysWithRealRsaModulus()
    {
        const string json = """
            {
              "Clients": [
                {
                  "ClientId": "oidf-fapi2-test",
                  "Jwks": {
                    "keys": [
                      {
                        "kty": "RSA",
                        "kid": "abblix-fapi2-client1-3c896038",
                        "use": "sig",
                        "alg": "PS256",
                        "n": "ulOIreKtMsORZrW2pI1obZ67NEV649xerW6Q9LNzOgQ0RUGrpNBub-AA2GqPWH0EgZ13BEXIHviqlk3BD94335ULNWiTbEL_vQso0xDmSBaRoRd5flEsjjcnAVt7bvkK_pLvpZgDZg869e6hG1zKuHD5Oa4CBfwg1F6Zy4uT_SwiKgEyAzOeGjZVO5Zcg17iIJll4tRB0D4pXNNrL9pW1Aih7EfKZZwffuPHMjvo57R4vyHglwuoA8Mcrf7oeuQIVVjOjZF-sFD-KVdNXuFPeWKjuIpu4_nRBLebcn6KHU276kXZtKYxrk-SpKoej1BYlvuKrWLwOvaFpH4fc9DHHQ",
                        "e": "AQAB"
                      }
                    ]
                  }
                }
              ]
            }
            """;
        var clients = ApplyConfig(json, new ClientInfo("oidf-fapi2-test"));

        var jwks = clients.Single().Jwks;
        Assert.NotNull(jwks);
        var key = Assert.IsType<RsaJsonWebKey>(jwks.Keys.Single());
        Assert.Equal("abblix-fapi2-client1-3c896038", key.KeyId);
        Assert.Equal("sig", key.Usage);
        Assert.Equal("PS256", key.Algorithm);
    }

    private static ClientInfo[] ApplyConfig(string json, params ClientInfo[] clients)
    {
        var config = new ConfigurationBuilder()
            .AddJsonStream(new MemoryStream(Encoding.UTF8.GetBytes(json)))
            .Build();

        return clients.WithJwksFromConfiguration(config.GetSection("Clients"));
    }
}
