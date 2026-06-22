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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Abblix.Oidc.Server.Mvc.UnitTests;

/// <summary>
/// Covers the framework-neutral mapping of validation messages onto the OAuth <c>invalid_request</c>
/// error. The scoping and short-circuit behaviour is covered by
/// <see cref="Filters.ReturnsOidcInvalidRequestTests"/>.
/// </summary>
public class ModelValidationErrorTests
{
    [Fact]
    public void InvalidRequest_FromMessages_JoinsAndSetsInvalidRequestCode()
    {
        var error = ModelValidationError.InvalidRequest(["first problem", "second problem"]);

        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Equal("first problem second problem", error.ErrorDescription);
    }

    [Fact]
    public void InvalidRequest_FromBlankOrNoMessages_FallsBackToGenericDescription()
    {
        string[][] blankCases = [[], [""], ["   "], ["", "   "]];

        foreach (var messages in blankCases)
        {
            var error = ModelValidationError.InvalidRequest(messages);

            Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
            Assert.False(string.IsNullOrWhiteSpace(error.ErrorDescription));
        }
    }

    [Fact]
    public void InvalidRequest_FromModelState_AggregatesErrorMessages()
    {
        var modelState = new ModelStateDictionary();
        modelState.AddModelError("response_mode", "The value 'bogus' is invalid");

        var error = ModelValidationError.InvalidRequest(modelState);

        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("bogus", error.ErrorDescription);
    }
}
