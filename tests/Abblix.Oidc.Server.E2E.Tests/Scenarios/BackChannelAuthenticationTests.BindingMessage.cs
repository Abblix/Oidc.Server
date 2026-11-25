// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Model;
using Xunit;
using CibaParameters = Abblix.Oidc.Server.Model.BackChannelAuthenticationRequest.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <remarks>
/// CIBA Core 1.0 section 7.1: "the binding_message value SHOULD be relatively short and use a limited set of plain text
/// characters"; section 13 answers one "invalid or unacceptable for use in the context of the given request" with
/// invalid_binding_message, under HTTP 400.
/// </remarks>
public partial class BackChannelAuthenticationTests
{
    public static TheoryData<string> UnacceptableBindingMessages => new()
    {
        new string('a', new BackChannelAuthenticationOptions().MaximumBindingMessageLength + 1),
        "Approve\npayment",
        "Pay \u202E0001",
    };

    /// <summary>
    /// A binding message longer than the maximum, or one carrying a code point that is not plain visible text, is
    /// refused with invalid_binding_message and 400.
    /// </summary>
    [Theory]
    [MemberData(nameof(UnacceptableBindingMessages))]
    public async Task An_unacceptable_binding_message_is_refused(string bindingMessage)
    {
        var (host, client, discovery, form) = await AcceptedRequestAsync();
        await using var _ = host;
        form.RemoveAll(pair => pair.Key == CibaParameters.BindingMessage);
        form.Add(new KeyValuePair<string, string>(CibaParameters.BindingMessage, bindingMessage));

        var response = await FormPostHelpers.PostFormAsync(client, discovery.BackChannelAuthenticationEndpoint!, form);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await ReadJsonAsync(response);
        Assert.Equal(ErrorCodes.InvalidBindingMessage, body[ErrorResponse.Parameters.Error]!.GetValue<string>());
    }

    /// <summary>
    /// A short binding message in another script, with an emoji, is accepted.
    /// </summary>
    [Fact]
    public async Task A_short_binding_message_in_any_script_is_accepted()
    {
        var (host, client, discovery, form) = await AcceptedRequestAsync();
        await using var _ = host;
        form.RemoveAll(pair => pair.Key == CibaParameters.BindingMessage);
        form.Add(new KeyValuePair<string, string>(CibaParameters.BindingMessage, "Подтвердите вход \U0001F600"));

        var response = await FormPostHelpers.PostFormAsync(client, discovery.BackChannelAuthenticationEndpoint!, form);

        Assert.True(response.IsSuccessStatusCode, (await ReadJsonAsync(response)).ToJsonString());
    }
}
