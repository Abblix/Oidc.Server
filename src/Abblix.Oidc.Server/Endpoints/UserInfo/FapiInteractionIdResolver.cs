// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.UserInfo;

/// <summary>
/// FAPI 1.0 Part 1 section 6.2.1, which Part 2 section 6.2.1 takes in: the protected resource "shall set the response
/// header x-fapi-interaction-id to the value received from the corresponding FAPI client request header or to a
/// RFC4122 UUID value if the request header was not provided to track the interaction" and "shall log the value of
/// x-fapi-interaction-id in the log entry". Applied where the profile in force carries
/// <see cref="SecurityProfileRequirements.RequireFapiInteractionId"/>.
/// </summary>
/// <param name="logger">Records the value each response carries.</param>
public partial class FapiInteractionIdResolver(ILogger<FapiInteractionIdResolver> logger) : IFapiInteractionIdResolver
{
    /// <summary>
    /// The RFC 4122 section 3 string representation, the hyphenated 8-4-4-4-12 hexadecimal form.
    /// </summary>
    private const string UuidFormat = "D";

    /// <inheritdoc />
    public string? Resolve(TenantDefinition tenant, ClientInfo? client, string? received)
    {
        if (!SecurityProfileRequirements.For(tenant, client).RequireFapiInteractionId)
            return null;

        if (received is null)
            return Answered(NewInteractionId());

        if (Guid.TryParseExact(received, UuidFormat, out _))
            return Answered(received);

        // Section 6.2.2 has the client's value "be a RFC4122 UUID", and section 6.2.1 lets the resource answer with the
        // client's value or a UUID of its own, so a value that is no UUID, a repeated header among them, is treated as
        // not provided. Our choice: no clause has the resource refuse the request over it, and echoing it would hand
        // back, and write to the log, text nothing has checked
        var replacement = NewInteractionId();
        LogMalformedInteractionIdReplaced(replacement);
        return Answered(replacement);
    }

    private string Answered(string interactionId)
    {
        LogInteractionIdAnswered(interactionId);
        return interactionId;
    }

    private static string NewInteractionId() => Guid.NewGuid().ToString(UuidFormat);
}
