// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// Verifies that <see cref="AuthorizationDetailsFilterValidator"/> refuses a filter that can only ever
/// delete data, rather than letting it surface later as a resource server reporting a permission it was
/// granted and cannot find.
/// </summary>
public class AuthorizationDetailsFilterValidatorTests
{
    private static readonly Uri Api = new("https://api.example.com");

    private readonly AuthorizationDetailsFilterValidator _validator = new();

    /// <summary>
    /// The shipped default leaves the filter off, so a stock configuration validates.
    /// </summary>
    [Fact]
    public void Validate_FilterOff_Succeeds()
    {
        var options = new OidcOptions();

        Assert.False(options.FilterAuthorizationDetailsByLocation);
        Assert.True(_validator.Validate(null, options).Succeeded);
    }

    /// <summary>
    /// The filter off and no resources is the same stock configuration, and stays valid.
    /// </summary>
    /// <remarks>
    /// The control that keeps the refusal below from being a refusal of an empty resource list. What is
    /// wrong is the combination, and a test that could not tell the two apart would pass over a validator
    /// that refused every deployment without resources.
    /// </remarks>
    [Fact]
    public void Validate_NoResourcesAndFilterOff_Succeeds()
    {
        var options = new OidcOptions { Resources = [] };

        Assert.True(_validator.Validate(null, options).Succeeded);
    }

    /// <summary>
    /// The filter on with a registered resource is the configuration it was written for.
    /// </summary>
    [Fact]
    public void Validate_FilterOnWithResources_Succeeds()
    {
        var options = new OidcOptions
        {
            FilterAuthorizationDetailsByLocation = true,
            Resources = [new ResourceDefinition(Api)],
        };

        Assert.True(_validator.Validate(null, options).Succeeded);
    }

    /// <summary>
    /// The filter on with nothing to filter to is refused, and the message says what to do about it.
    /// </summary>
    /// <remarks>
    /// With no resource registered, nothing can put one in the audience: a request naming one is refused as
    /// <c>invalid_target</c> before it gets that far, and a default resource indicator cannot be set,
    /// because the validator beside this one requires it to name a registered resource. So the audience is
    /// the issuer on every token, no locations value can match it, and every located entry is dropped from
    /// everything this server issues - always, rather than for a namespace mismatch a host could reason
    /// about from the option's own remarks.
    /// </remarks>
    [Fact]
    public void Validate_FilterOnWithNoResources_Fails()
    {
        var options = new OidcOptions { FilterAuthorizationDetailsByLocation = true };

        var result = _validator.Validate(null, options);

        Assert.False(result.Succeeded);
        Assert.Contains(
            nameof(OidcOptions.FilterAuthorizationDetailsByLocation),
            result.FailureMessage,
            StringComparison.Ordinal);
        Assert.Contains(
            nameof(OidcOptions.Resources), result.FailureMessage, StringComparison.Ordinal);
    }
}
