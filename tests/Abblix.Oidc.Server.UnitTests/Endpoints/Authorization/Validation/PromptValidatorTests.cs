// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.Validation;

/// <summary>
/// Pins the one combination of <c>prompt</c> values OpenID Connect Core 1.0, section 3.1.2.1, refuses: none with
/// any other value. A repeat of none is not another value.
/// </summary>
public class PromptValidatorTests
{
    private static AuthorizationValidationContext ContextWith(string[]? prompt) => new(new AuthorizationRequest
    {
        ClientId = TestConstants.DefaultClientId,
        ResponseType = [ResponseTypes.Code],
        RedirectUri = TestConstants.DefaultRedirectUri,
        Scope = [Scopes.OpenId],
        Prompt = prompt,
    })
    {
        ClientInfo = new ClientInfo(TestConstants.DefaultClientId),
        ResponseMode = ResponseModes.Query,
    };

    public static TheoryData<string[]> Accepted => new()
    {
        Array.Empty<string>(),
        new[] { Prompts.None },
        new[] { Prompts.None, Prompts.None },
        new[] { Prompts.Login, Prompts.Consent },
        new[] { Prompts.Create, Prompts.SelectAccount, Prompts.Login, Prompts.Consent },
    };

    public static TheoryData<string[]> Refused => new()
    {
        new[] { Prompts.None, Prompts.Login },
        new[] { Prompts.Consent, Prompts.None },
        new[] { Prompts.None, Prompts.None, Prompts.SelectAccount },
    };

    [Theory]
    [MemberData(nameof(Accepted))]
    public async Task APromptWithoutNoneBesideAnotherValue_IsAccepted(string[] prompt)
        => Assert.Null(await new PromptValidator().ValidateAsync(ContextWith(prompt)));

    [Fact]
    public async Task ARequestWithoutPrompt_IsAccepted()
        => Assert.Null(await new PromptValidator().ValidateAsync(ContextWith(null)));

    [Theory]
    [MemberData(nameof(Refused))]
    public async Task NoneBesideAnotherValue_IsRefusedAsAnInvalidRequest(string[] prompt)
    {
        var error = await new PromptValidator().ValidateAsync(ContextWith(prompt));

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }
}
