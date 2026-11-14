// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server


using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using System.Text.Json;
using System.Text.Json.Serialization;
using Abblix.Jwt;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.Consents;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
#if MINIMAL_API_TRANSPORT
using Abblix.Oidc.Server.MinimalApi;
#else
using Abblix.Oidc.Server.Mvc;
#endif

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// The JWK Set the server publishes is written with the library's own options, so a string converter the host
/// registers for its own payloads, in its MVC options and in its HTTP options alike, does not rewrite the keys
/// relying parties fetch.
/// </summary>
public sealed class JsonWebKeySetHostOptionsTests : IAsyncLifetime
{
    private const string KeyId = "signing-key-1";

    private WebApplication _app = null!;

    public async ValueTask InitializeAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddControllers()
            .AddJsonOptions(options => options.JsonSerializerOptions.Converters.Add(new MarkingStringConverter()));
        builder.Services.ConfigureHttpJsonOptions(
            options => options.SerializerOptions.Converters.Add(new MarkingStringConverter()));
        builder.Services.AddCors();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();

        var signingKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        signingKey.KeyId = KeyId;
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services.AddOidcServices(options => TestTenant.ServeOn(options, signingKey));

        _app = builder.Build();
        _app.UseMultiTenancy();
        _app.UseCors();
#if MINIMAL_API_TRANSPORT
        _app.MapOidcEndpoints();
#else
        _app.MapControllers();
        _app.MapOidcControllers();
#endif
        await _app.StartAsync(TestContext.Current.CancellationToken);
    }

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();

    [Fact]
    public async Task TheJwkSet_IsPublishedAsTheKeysAre_WhateverStringConverterTheHostRegistered()
    {
        using var client = _app.GetTestClient();
        client.BaseAddress = TestServerAddress.BaseAddress;

        var json = await client.GetStringAsync("/.well-known/jwks", TestContext.Current.CancellationToken);

        var key = Assert.Single(JsonDocument.Parse(json).RootElement.GetProperty("keys").EnumerateArray());
        Assert.Equal(JsonWebKeyTypes.Rsa, key.GetProperty("kty").GetString());
        Assert.Equal(KeyId, key.GetProperty("kid").GetString());
        Assert.Equal(PublicKeyUsages.Signature, key.GetProperty("use").GetString());
        Assert.Equal(SigningAlgorithms.RS256, key.GetProperty("alg").GetString());
    }

    /// <summary>
    /// A host that rewrites every string it serializes, as a global sanitizing converter might: it appends a mark,
    /// so any member it reaches reads differently, whatever its case.
    /// </summary>
    private sealed class MarkingStringConverter : JsonConverter<string>
    {
        public override string? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            => reader.GetString() + "~host";

        public override void Write(Utf8JsonWriter writer, string value, JsonSerializerOptions options)
            => writer.WriteStringValue(value + "~host");
    }
}
