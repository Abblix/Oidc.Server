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
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.Validation;

/// <summary>
/// What the authorization endpoint records from the <c>authorization_details</c> policy, and what it
/// refuses to record.
/// </summary>
/// <remarks>
/// The policy itself is covered in <c>AuthorizationDetailsPolicyTests</c>; this is the adapter between it
/// and the request context, and the reason it needs tests of its own is that the two are separately
/// replaceable. <see cref="IAuthorizationDetailsPolicy"/> is public and registered with TryAdd, so a host
/// supplies its own or wraps ours, and the adapter is where that answer meets the request.
/// </remarks>
public class AuthorizationDetailsRequestValidatorTests
{
    private static readonly JsonArray Requested = new(new JsonObject { ["type"] = "payment_initiation" });

    private static AuthorizationValidationContext Context(JsonArray? authorizationDetails)
        => new(
            new AuthorizationRequest
            {
                ClientId = TestConstants.DefaultClientId,
                ResponseType = [ResponseTypes.Code],
                RedirectUri = TestConstants.DefaultRedirectUri,
                Scope = [Scopes.OpenId],
                AuthorizationDetails = authorizationDetails,
            })
        {
            ClientInfo = new ClientInfo(TestConstants.DefaultClientId),
            ResponseMode = ResponseModes.Query,
        };

    /// <summary>
    /// What survived validation is what the request carries onward.
    /// </summary>
    [Fact]
    public async Task WhatThePolicyAccepts_IsRecorded()
    {
        var context = Context((JsonArray)Requested.DeepClone());
        var validator = new AuthorizationDetailsRequestValidator(StubAuthorizationDetailsPolicy.Accepting);

        Assert.Null(await validator.ValidateAsync(context));

        Assert.NotNull(context.AuthorizationDetails);
        Assert.Single(context.AuthorizationDetails);
    }

    /// <summary>
    /// A request that carried none records none, which is the only shape an empty answer may mean.
    /// </summary>
    [Fact]
    public async Task ARequestWithoutAuthorizationDetails_RecordsNothing()
    {
        var context = Context(null);
        var validator = new AuthorizationDetailsRequestValidator(StubAuthorizationDetailsPolicy.Accepting);

        Assert.Null(await validator.ValidateAsync(context));

        Assert.Null(context.AuthorizationDetails);
    }

    /// <summary>
    /// The policy's refusal reaches the client as the error the specification names for it.
    /// </summary>
    [Fact]
    public async Task WhatThePolicyRefuses_IsAnInvalidAuthorizationDetailsError()
    {
        var context = Context((JsonArray)Requested.DeepClone());
        var validator = new AuthorizationDetailsRequestValidator(
            StubAuthorizationDetailsPolicy.Refusing("amount exceeds the client's cap"));

        var error = await validator.ValidateAsync(context);

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidAuthorizationDetails, error.Error);
    }

    /// <summary>
    /// A policy that drops every entry of a request that carried some is a fault, not consent.
    /// </summary>
    /// <remarks>
    /// Dropping every entry says the request may not be honoured as asked, which the contract requires to
    /// be returned as a refusal. Recorded as "nothing to forward" instead, the request would be authorized
    /// with its <c>authorization_details</c> gone, and neither the client nor the resource server can see
    /// that it happened - so the fault is raised where it can still be read, rather than at the resource
    /// server wondering why a payment carried no amount.
    /// </remarks>
    [Fact]
    public async Task APolicyThatDropsEveryEntry_IsAFault()
    {
        var context = Context((JsonArray)Requested.DeepClone());
        var validator = new AuthorizationDetailsRequestValidator(StubAuthorizationDetailsPolicy.Emptying);

        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(
            () => validator.ValidateAsync(context));

        Assert.Contains(nameof(IAuthorizationDetailsPolicy), thrown.Message, StringComparison.Ordinal);
        Assert.Null(context.AuthorizationDetails);
    }
}
