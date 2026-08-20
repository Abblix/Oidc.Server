// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.SecureHttpFetch;

/// <summary>
/// Pins the scheme allowlist to what a configuration file says. This is an allowlist consumed by
/// SSRF validation, so the failure worth testing is widening: a default held in the property is
/// added to by the configuration binder rather than replaced, and a host that configures plain
/// HTTP would silently keep HTTPS allowed beside it.
/// </summary>
public class SecureHttpFetchOptionsBindingTests
{
    private static SecureHttpFetchOptions Bind(Dictionary<string, string?> values)
        => new ConfigurationBuilder()
            .AddInMemoryCollection(values)
            .Build()
            .GetSection("SecureHttpFetch")
            .Get<SecureHttpFetchOptions>()!;

    /// <summary>
    /// A file that names one scheme gets that one scheme, not the union of the file and the default.
    /// </summary>
    [Fact]
    public void Bind_SchemeList_ReplacesRatherThanExtends()
    {
        var options = Bind(new Dictionary<string, string?>
        {
            ["SecureHttpFetch:AllowedSchemes:0"] = Uri.UriSchemeHttp,
        });

        Assert.NotNull(options.AllowedSchemes);
        Assert.Equal([Uri.UriSchemeHttp], options.AllowedSchemes);
        Assert.Equal([Uri.UriSchemeHttp], options.EffectiveAllowedSchemes);
    }

    /// <summary>
    /// A file that says nothing leaves the restriction at the library's default, which is HTTPS
    /// alone. The default lives in the effective accessor, because held in the property it would
    /// leak into every bound list.
    /// </summary>
    [Fact]
    public void Bind_WithoutSchemes_KeepsTheHttpsDefault()
    {
        var options = Bind(new Dictionary<string, string?>
        {
            ["SecureHttpFetch:BlockPrivateNetworks"] = "true",
        });

        Assert.Null(options.AllowedSchemes);
        Assert.Equal([Uri.UriSchemeHttps], options.EffectiveAllowedSchemes);
    }

    /// <summary>
    /// An empty value is a statement, not an omission: it lifts the scheme restriction entirely,
    /// and it is how a file expresses that - null has no spelling in configuration.
    /// </summary>
    [Fact]
    public void Bind_ExplicitlyEmptySchemes_LiftTheRestriction()
    {
        var options = Bind(new Dictionary<string, string?>
        {
            ["SecureHttpFetch:AllowedSchemes"] = "",
        });

        Assert.NotNull(options.AllowedSchemes);
        Assert.Empty(options.AllowedSchemes);
        Assert.Empty(options.EffectiveAllowedSchemes);
    }

    /// <summary>
    /// The same three statements made in code, because a host that builds its options in C# needs
    /// the identical contract.
    /// </summary>
    [Fact]
    public void ConstructedInCode_FollowsTheSameContract()
    {
        Assert.Equal([Uri.UriSchemeHttps], new SecureHttpFetchOptions().EffectiveAllowedSchemes);
        Assert.Empty(new SecureHttpFetchOptions { AllowedSchemes = [] }.EffectiveAllowedSchemes);
        Assert.Equal(
            [Uri.UriSchemeHttp],
            new SecureHttpFetchOptions { AllowedSchemes = [Uri.UriSchemeHttp] }.EffectiveAllowedSchemes);
    }

    /// <summary>
    /// A lifted restriction is a statement a deployment may mean, so it is reported rather than
    /// refused - and only the lifted case is, or the report trains everyone to ignore it.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Validator_ReportsLiftedRestriction_OnlyWhenTheListIsEmpty(bool lifted)
    {
        var logger = new CapturingLogger<SecureUriValidator>();
        var options = new SecureHttpFetchOptions { AllowedSchemes = lifted ? [] : null };

        _ = new SecureUriValidator(Microsoft.Extensions.Options.Options.Create(options), logger);

        if (lifted)
        {
            var (level, eventId) = Assert.Single(logger.Entries);
            Assert.Equal(LogLevel.Warning, level);
            Assert.Equal(LogEvents.HttpFetch.SecureUriValidator.SchemeRestrictionLifted, eventId.Id);
        }
        else
        {
            Assert.Empty(logger.Entries);
        }
    }

    /// <summary>
    /// Minimal <see cref="ILogger{TCategoryName}"/> that records the level and event of each entry,
    /// so a test can assert the report without coupling to the <c>[LoggerMessage]</c> call shape.
    /// </summary>
    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<(LogLevel Level, EventId EventId)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, eventId));
    }
}
