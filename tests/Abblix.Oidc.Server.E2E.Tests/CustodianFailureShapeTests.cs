// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Runtime.CompilerServices;
using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests;

/// <summary>
/// What a caller is told when the keys the server signs with cannot be reached. The two adapters answer the same
/// request, so they owe the same answer: a host that swaps one for the other and finds its clients behaving
/// differently has been given a difference nobody chose. This file is compiled into both suites and binds to
/// whichever host factory the project supplies, so the two cannot drift apart by an edit to one of them.
/// </summary>
public sealed class CustodianFailureShapeTests
{
    /// <summary>
    /// A custodian that refuses, naming the key that was asked for so a test can tell which enumeration the
    /// response came from.
    /// </summary>
    private sealed class FailingCustodian(Func<string, Exception> failure) : IKeyCustodian
    {
        public Task<byte[]> SignAsync(
            string keyId, string algorithm, byte[] data, CancellationToken cancellationToken)
            => throw failure(keyId);

        public Task<byte[]?> UnwrapKeyAsync(
            string keyId,
            string algorithm,
            JsonWebTokenHeader header,
            byte[] encryptedKey,
            CancellationToken cancellationToken)
            => throw failure(keyId);

        public Task<byte[]?> AgreeKeyAsync(
            string keyId, string algorithm, JsonWebKey ephemeralPublicKey, CancellationToken cancellationToken)
            => throw failure(keyId);

        public bool ServesKeyManagement(string algorithm) => true;

        public async IAsyncEnumerable<KeyVersion> GetKeyVersionsAsync(
            string keyName, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await Task.Yield();
            throw failure(keyName);
#pragma warning disable CS0162 // Unreachable, and required: a method without a yield is not an iterator.
            yield break;
#pragma warning restore CS0162
        }
    }

    /// <summary>
    /// A client of the test host whose tenant keeps its keys in a custodian that refuses as
    /// <paramref name="failure"/> says.
    /// </summary>
    private static HttpClient ClientWhoseKeysFail(TestFactory factory, Func<string, Exception> failure)
        => factory
            .WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            {
                services.AddSingleton<IKeyCustodian>(new FailingCustodian(failure));
                services.AddCustodian<FailingCustodian>().UseKeysInCustodian();
                services.PostConfigure<TestTenantSettings>(tenant =>
                {
                    tenant.SigningKeys = [];
                    tenant.CustodianKeys = new CustodianHeldKeys { SigningKeyName = "signing" };
                });
            }))
            .CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false,
                BaseAddress = TestServerAddress.BaseAddress,
            });

    private static readonly Uri Keys = new("/.well-known/jwks", UriKind.Relative);

    [Fact]
    public async Task AnUnavailableCustodianAnswers503WithRetryAfter()
    {
        using var factory = new TestFactory();
        using var client = ClientWhoseKeysFail(
            factory,
            role => new KeyCustodianUnavailableException(role, "sealed", TimeSpan.FromSeconds(30)));

        var response = await client.GetAsync(Keys, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal(TimeSpan.FromSeconds(30), response.Headers.RetryAfter?.Delta);
    }

    [Fact]
    public async Task ACustodianFailureThatWillNotClearAnswers500()
    {
        using var factory = new TestFactory();
        using var client = ClientWhoseKeysFail(
            factory,
            role => new KeyCustodianFailedException(
                role,
                new InvalidOperationException("the identity lacks the permission")));

        var response = await client.GetAsync(Keys, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Null(response.Headers.RetryAfter);
    }

    [Fact]
    public async Task NeitherAnswerCarriesTheExceptionText()
    {
        using var factory = new TestFactory();
        using var client = ClientWhoseKeysFail(
            factory,
            role => new KeyCustodianFailedException(
                role,
                new InvalidOperationException("transit/keys/oidc-sign failed with 503")));

        var response = await client.GetAsync(Keys, TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.DoesNotContain("transit/keys/oidc-sign", body);
        Assert.DoesNotContain(nameof(KeyCustodianFailedException), body);
    }

    /// <summary>
    /// The control. Without it <see cref="AnUnavailableCustodianAnswers503WithRetryAfter"/>,
    /// <see cref="ACustodianFailureThatWillNotClearAnswers500"/> and
    /// <see cref="NeitherAnswerCarriesTheExceptionText"/> pass on a server that refuses everything, which is
    /// exactly the change somebody might make while trying to satisfy them.
    /// </summary>
    [Fact]
    public async Task AHealthyProviderStillPublishesItsKeys()
    {
        using var factory = new TestFactory();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });

        var response = await client.GetAsync(Keys, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("\"keys\"", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }
}
