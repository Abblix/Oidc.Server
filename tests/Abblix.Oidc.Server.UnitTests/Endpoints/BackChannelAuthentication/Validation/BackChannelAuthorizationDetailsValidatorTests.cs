// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// What the decoupled endpoint records from the <c>authorization_details</c> policy, and what it refuses
/// to record.
/// </summary>
/// <remarks>
/// The same adapter shape as the authorization endpoint's, against a different context, and it needs
/// tests of its own for the reason a shared guard usually fails: written once and driven on one of the
/// paths it was added to.
/// </remarks>
public class BackChannelAuthorizationDetailsValidatorTests
{
    private static readonly JsonArray Requested = new(new JsonObject { ["type"] = "payment_initiation" });

    private static BackChannelAuthenticationValidationContext Context(JsonArray? authorizationDetails)
        => new(
            new BackChannelAuthenticationRequest { AuthorizationDetails = authorizationDetails },
            new ClientRequest())
        {
            ClientInfo = new ClientInfo(TestConstants.DefaultClientId),
        };

    /// <summary>
    /// What survived validation is what the request carries onward.
    /// </summary>
    [Fact]
    public async Task WhatThePolicyAccepts_IsRecorded()
    {
        var context = Context((JsonArray)Requested.DeepClone());
        var validator = new BackChannelAuthorizationDetailsValidator(StubAuthorizationDetailsPolicy.Accepting);

        Assert.Null(await validator.ValidateAsync(context));

        Assert.NotNull(context.AuthorizationDetails);
        Assert.Single(context.AuthorizationDetails);
    }

    /// <summary>
    /// The policy's refusal travels as the error the specification names for it.
    /// </summary>
    [Fact]
    public async Task WhatThePolicyRefuses_IsAnInvalidAuthorizationDetailsError()
    {
        var context = Context((JsonArray)Requested.DeepClone());
        var validator = new BackChannelAuthorizationDetailsValidator(
            StubAuthorizationDetailsPolicy.Refusing("amount exceeds the client's cap"));

        var error = await validator.ValidateAsync(context);

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidAuthorizationDetails, error.Error);
    }

    /// <summary>
    /// A policy that drops every entry of a request that carried some is a fault, not consent.
    /// </summary>
    /// <remarks>
    /// Driven in both shapes, because the two are told apart only by WHERE the request is counted: a
    /// policy answering with a fresh empty array, and one that empties the array it was handed as it
    /// answers. The second is what every narrowing validator in this repository looks like.
    /// </remarks>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task APolicyThatDropsEveryEntry_IsAFault(bool inPlace)
    {
        var context = Context((JsonArray)Requested.DeepClone());
        var validator = new BackChannelAuthorizationDetailsValidator(
            inPlace
                ? StubAuthorizationDetailsPolicy.ClearingInPlace
                : StubAuthorizationDetailsPolicy.Emptying);

        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(
            () => validator.ValidateAsync(context));

        Assert.Contains(nameof(IAuthorizationDetailsPolicy), thrown.Message, StringComparison.Ordinal);
        Assert.Null(context.AuthorizationDetails);
    }
}
