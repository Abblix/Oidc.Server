// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization.Metadata;
using Abblix.Jwt;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Lays the client metadata a software statement carries over the metadata of a registration request. RFC 7591
/// section 3.1.1: "If the server supports software statements, client metadata values conveyed in the software
/// statement MUST take precedence over those conveyed using plain JSON elements".
/// </summary>
/// <remarks>
/// A member is the statement's when the statement names it, whatever its value, so a stated default or an explicit
/// null replaces the body's value as any other does. Members are matched by the serializer's own contract of
/// <see cref="ClientRegistrationRequest"/>, the one a request body is read with, so a member the request models is
/// laid over under the name it is read by; a member it does not model joins
/// <see cref="ClientRegistrationRequest.AdditionalMembers"/> in the same way.
/// </remarks>
internal static class SoftwareStatementMetadata
{
    private static readonly JsonTypeInfo<ClientRegistrationRequest> Contract =
        (JsonTypeInfo<ClientRegistrationRequest>)JsonSerializerOptions.Default.GetTypeInfo(
            typeof(ClientRegistrationRequest));

    /// <summary>
    /// The claims of a statement that are not client metadata: the values the server issues and the request names
    /// (RFC 7591 section 3.2.1 and 3.1.1), and the claims RFC 7519 section 4.1 registers for the JWT itself.
    /// </summary>
    private static readonly HashSet<string> NotMetadata =
    [
        ClientRegistrationRequest.Parameters.ClientId,
        ClientRegistrationRequest.Parameters.ClientSecret,
        ClientRegistrationRequest.Parameters.SoftwareStatement,
        IanaClaimTypes.Iss,
        IanaClaimTypes.Sub,
        IanaClaimTypes.Aud,
        IanaClaimTypes.Exp,
        IanaClaimTypes.Nbf,
        IanaClaimTypes.Iat,
        IanaClaimTypes.Jti,
    ];

    /// <summary>
    /// <paramref name="request"/> with every client metadata member <paramref name="claims"/> names taking the
    /// statement's value, or a description of why the claims do not read as client metadata.
    /// </summary>
    /// <param name="request">The registration metadata the statement takes precedence over.</param>
    /// <param name="claims">The payload of the software statement.</param>
    public static Result<ClientRegistrationRequest, string> OverlaidOn(
        ClientRegistrationRequest request,
        JsonObject claims)
    {
        var metadata = new JsonObject();
        foreach (var (name, value) in claims)
        {
            if (!NotMetadata.Contains(name))
                metadata[name] = value?.DeepClone();
        }

        ClientRegistrationRequest statement;
        try
        {
            statement = metadata.Deserialize(Contract) ?? throw new JsonException("The claims read as null");
        }
        catch (Exception exception) when (exception is JsonException or NotSupportedException or FormatException)
        {
            return exception.Message;
        }

        var overlaid = request with
        {
            AdditionalMembers = OverlaidOn(request.AdditionalMembers, statement.AdditionalMembers),
        };

        foreach (var property in Contract.Properties)
        {
            if (property is { IsExtensionData: false, Get: { } get, Set: { } set } &&
                metadata.ContainsKey(property.Name))
            {
                set(overlaid, get(statement));
            }
        }

        return overlaid;
    }

    private static Dictionary<string, JsonElement>? OverlaidOn(
        IDictionary<string, JsonElement>? body,
        IDictionary<string, JsonElement>? statement)
    {
        if (body is null && statement is null)
            return null;

        var members = new Dictionary<string, JsonElement>(body ?? new Dictionary<string, JsonElement>());
        foreach (var (name, value) in statement ?? new Dictionary<string, JsonElement>())
            members[name] = value;

        return members;
    }
}
