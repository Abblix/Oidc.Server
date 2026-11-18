// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.UserInfo;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.UserInfo;

/// <summary>
/// FAPI 1.0 Part 1 section 6.2.1: the resource "shall set the response header x-fapi-interaction-id" to the client's
/// value or a UUID, and "shall log the value of x-fapi-interaction-id in the log entry". Both halves are held here for
/// the profile in force, the tenant's where no client is known.
/// </summary>
public class FapiInteractionIdResolverTests
{
    private const string ClientValue = "c770aef3-6784-41f7-8e0e-ff5f97bddb3a";

    private readonly RecordingLoggerFactory _loggers = new();

    private FapiInteractionIdResolver Resolver() => new(new Logger<FapiInteractionIdResolver>(_loggers));

    /// <summary>
    /// The client's value is answered and logged as sent, in either case: RFC 4122 section 3 has the hexadecimal digits
    /// "case insensitive on input".
    /// </summary>
    [Theory]
    [InlineData(ClientValue)]
    [InlineData("C770AEF3-6784-41F7-8E0E-FF5F97BDDB3A")]
    public void TheClientsValue_IsAnsweredAndLogged(string received)
    {
        var answered = Resolver().Resolve(SingleIssuer.Tenant, ClientSecurityProfile.Fapi1Advanced, received);

        Assert.Equal(received, answered);
        var record = Assert.Single(_loggers.Entries);
        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(received, record.Value("InteractionId"));
    }

    /// <summary>
    /// A value that is no UUID in the RFC 4122 string form is answered and logged as a UUID of the server's own, and
    /// never written to the log as received: text the platform's parser tolerates, a sign, a hex prefix or padding,
    /// is not that form either.
    /// </summary>
    [Theory]
    [InlineData("forged\r\nline")]
    [InlineData("+770aef3-6784-41f7-8e0e-ff5f97bddb3a")]
    [InlineData("0x70aef3-6784-41f7-8e0e-ff5f97bddb3a")]
    [InlineData("c770aef3-+784-41f7-8e0e-ff5f97bddb3a")]
    [InlineData(" c770aef3-6784-41f7-8e0e-ff5f97bddb3a")]
    [InlineData("c770aef3-6784-41f7-8e0e-ff5f97bddb3a ")]
    [InlineData("\tc770aef3-6784-41f7-8e0e-ff5f97bddb3a")]
    public void AMalformedValue_IsReplacedAndNeverLogged(string received)
    {
        var answered = Resolver().Resolve(SingleIssuer.Tenant, ClientSecurityProfile.Fapi1Advanced, received);

        Assert.True(Guid.TryParseExact(answered, "D", out _), answered);
        Assert.NotEqual(received, answered);
        Assert.Contains(_loggers.Entries, record => record.Level == LogLevel.Warning);
        Assert.All(_loggers.Entries, record => Assert.DoesNotContain(received, record.Message));
        Assert.Equal(answered, _loggers.Entries[^1].Value("InteractionId"));
    }

    [Fact]
    public void AClientUnderNoProfile_GetsNoValueAndNoLog()
    {
        Assert.Null(Resolver().Resolve(SingleIssuer.Tenant, null, ClientValue));
        Assert.Empty(_loggers.Entries);
    }

    /// <summary>
    /// A request refused before its token named a client is answered under the tenant's profile.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, true)]
    [InlineData(ClientSecurityProfile.Fapi2, false)]
    [InlineData(ClientSecurityProfile.None, false)]
    public void WithNoClientKnown_TheTenantsProfileDecides(ClientSecurityProfile profile, bool answered)
    {
        var tenant = new TestIssuer { DefaultSecurityProfile = profile }.ToTenant();

        Assert.Equal(answered ? ClientValue : null, Resolver().Resolve(tenant, null, ClientValue));
    }
}
