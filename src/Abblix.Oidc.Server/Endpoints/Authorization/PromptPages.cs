// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server


namespace Abblix.Oidc.Server.Endpoints.Authorization;

/// <summary>
/// The pages a request's <c>prompt</c> sends the end user to, each answered once: the server stamps the request when
/// it sends the end user to a page, and a page is answered by what the host wrote since that stamp.
/// </summary>
internal static class PromptPages
{
    /// <summary>
    /// Whether <paramref name="model"/> asks for <paramref name="prompt"/>.
    /// </summary>
    public static bool Asks(Model.AuthorizationRequest model, string prompt)
        => model.Prompt?.Contains(prompt, StringComparer.Ordinal) is true;

    /// <summary>
    /// The request stamped as sending the end user to the page of <paramref name="prompt"/> at <paramref name="now"/>.
    /// </summary>
    public static Model.AuthorizationRequest Stamped(Model.AuthorizationRequest model, string prompt, DateTimeOffset now)
    {
        var prompted = new Dictionary<string, DateTimeOffset>(model.Prompted ?? new Dictionary<string, DateTimeOffset>())
        {
            [prompt] = now,
        };
        return model with { Prompted = prompted };
    }

    /// <summary>
    /// Whether <paramref name="writtenAt"/>, the moment the host wrote what answers the page of
    /// <paramref name="prompt"/>, comes after the server sent the end user to that page.
    /// </summary>
    /// <remarks>
    /// The host's moments are kept to the second, as an authentication time is, so the comparison is too.
    /// </remarks>
    public static bool AnsweredBy(Model.AuthorizationRequest model, string prompt, DateTimeOffset? writtenAt)
        => model.Prompted?.TryGetValue(prompt, out var sentAt) is true &&
           writtenAt is { } written &&
           sentAt.ToUnixTimeSeconds() <= written.ToUnixTimeSeconds();
}
