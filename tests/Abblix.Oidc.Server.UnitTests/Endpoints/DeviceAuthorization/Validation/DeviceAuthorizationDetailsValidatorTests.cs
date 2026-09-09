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
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DeviceAuthorization.Validation;

/// <summary>
/// What the device endpoint records from the <c>authorization_details</c> policy, and what it refuses to
/// record.
/// </summary>
/// <remarks>
/// The third of three adapters around one policy. They are separately replaceable and separately wrong,
/// so each drives the guard it carries rather than inheriting confidence from its neighbours.
/// </remarks>
public class DeviceAuthorizationDetailsValidatorTests
{
    private static readonly JsonArray Requested = new(new JsonObject { ["type"] = "payment_initiation" });

    private static DeviceAuthorizationValidationContext Context(JsonArray? authorizationDetails)
        => new(
            new DeviceAuthorizationRequest { AuthorizationDetails = authorizationDetails },
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
        var validator = new DeviceAuthorizationDetailsValidator(StubAuthorizationDetailsPolicy.Accepting);

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
        var validator = new DeviceAuthorizationDetailsValidator(
            StubAuthorizationDetailsPolicy.Refusing("amount exceeds the client's cap"));

        var error = await validator.ValidateAsync(context);

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidAuthorizationDetails, error.Error);
    }

    /// <summary>
    /// A policy that drops every entry of a request that carried some is a fault, not consent.
    /// </summary>
    /// <remarks>
    /// Both shapes, since the two are told apart only by where the request is counted: an answer built
    /// fresh, and one that empties the array the adapter handed over.
    /// </remarks>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task APolicyThatDropsEveryEntry_IsAFault(bool inPlace)
    {
        var context = Context((JsonArray)Requested.DeepClone());
        var validator = new DeviceAuthorizationDetailsValidator(
            inPlace
                ? StubAuthorizationDetailsPolicy.ClearingInPlace
                : StubAuthorizationDetailsPolicy.Emptying);

        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(
            () => validator.ValidateAsync(context));

        Assert.Contains(nameof(IAuthorizationDetailsPolicy), thrown.Message, StringComparison.Ordinal);
        Assert.Null(context.AuthorizationDetails);
    }
}
