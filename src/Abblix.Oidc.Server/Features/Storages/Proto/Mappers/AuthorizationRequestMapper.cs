// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Globalization;
using System.Text.Json.Nodes;
using Google.Protobuf.WellKnownTypes;

namespace Abblix.Oidc.Server.Features.Storages.Proto.Mappers;

/// <summary>
/// Maps between AuthorizationRequest C# record and protobuf message.
/// </summary>
internal static class AuthorizationRequestMapper
{
    /// <summary>
    /// Converts a C# AuthorizationRequest record to a protobuf message.
    /// </summary>
    public static AuthorizationRequest ToProto(this Model.AuthorizationRequest source)
    {
        var proto = new AuthorizationRequest();

        proto.Scope.AddRange(source.Scope);
        proto.ResponseType.AddIfNotNull(source.ResponseType);
        proto.AcrValues.AddIfNotNull(source.AcrValues);

        proto.Claims = source.Claims?.ToProto();

        CopyOptionalScalars(source, proto);

        if (source.MaxAge.HasValue)
            proto.MaxAge = Duration.FromTimeSpan(source.MaxAge.Value);

        if (source.PromptedAt.HasValue)
            proto.PromptedAt = source.PromptedAt.Value.ToTimestamp();

        proto.UiLocales.AddIfNotNull(source.UiLocales, c => c.Name);
        proto.ClaimsLocales.AddIfNotNull(source.ClaimsLocales, c => c.Name);
        proto.Resources.AddIfNotNull(source.Resources, u => u.OriginalString);

        // RFC 9396 authorization_details persisted as the raw JsonArray's JSON string -
        // byte-exact preservation for PAR storage between /par submission and the
        // front-channel /authorize redemption.
        if (source.AuthorizationDetails is { Count: > 0 } authorizationDetails)
            proto.AuthorizationDetailsJson = authorizationDetails.ToJsonString();

        return proto;
    }

    private static void CopyOptionalScalars(Model.AuthorizationRequest source, AuthorizationRequest proto)
    {
        SetIfPresent(proto, source.ClientId, static (message, value) => message.ClientId = value);
        SetIfPresent(proto, source.RedirectUri?.OriginalString, static (message, value) => message.RedirectUri = value);
        SetIfPresent(proto, source.State, static (message, value) => message.State = value);
        SetIfPresent(proto, source.ResponseMode, static (message, value) => message.ResponseMode = value);
        SetIfPresent(proto, source.Nonce, static (message, value) => message.Nonce = value);
        SetIfPresent(proto, source.Display, static (message, value) => message.Display = value);
        SetIfPresent(
            proto,
            source.Prompt is { } prompt ? string.Join(' ', prompt) : null,
            static (message, value) => message.Prompt = value);
        SetIfPresent(proto, source.IdTokenHint, static (message, value) => message.IdTokenHint = value);
        SetIfPresent(proto, source.LoginHint, static (message, value) => message.LoginHint = value);
        SetIfPresent(proto, source.CodeChallenge, static (message, value) => message.CodeChallenge = value);
        SetIfPresent(proto, source.CodeChallengeMethod, static (message, value) => message.CodeChallengeMethod = value);
        SetIfPresent(proto, source.Request, static (message, value) => message.Request = value);
        SetIfPresent(proto, source.RequestUri?.OriginalString, static (message, value) => message.RequestUri = value);
        SetIfPresent(proto, source.ProofKeyThumbprint, static (message, value) => message.ProofKeyThumbprint = value);
        SetIfPresent(
            proto,
            source.OriginRequestUri?.OriginalString,
            static (message, value) => message.OriginRequestUri = value);
    }

    /// <summary>
    /// Sets an optional message field only when the record carries a value for it.
    /// </summary>
    /// <remarks>
    /// The one rule every optional scalar follows, held here rather than repeated per field: a protobuf field
    /// refuses null, and an unset field is how the message says the record had none, which
    /// <see cref="ProtoMapper.GetString"/> reads back as null.
    /// </remarks>
    private static void SetIfPresent(
        AuthorizationRequest proto,
        string? value,
        Action<AuthorizationRequest, string> set)
    {
        if (value != null)
            set(proto, value);
    }

    /// <summary>
    /// Converts a protobuf AuthorizationRequest message to a C# record.
    /// </summary>
    public static Model.AuthorizationRequest FromProto(this AuthorizationRequest source)
    {
        return new Model.AuthorizationRequest
        {
            Scope = source.Scope.ToArray(),
            Claims = source.Claims?.FromProto(),
            ResponseType = source.ResponseType.GetArray(),
            ClientId = ProtoMapper.GetString(source.ClientId, source.HasClientId),
            RedirectUri = ProtoMapper.GetUri(source.RedirectUri, source.HasRedirectUri),
            State = ProtoMapper.GetString(source.State, source.HasState),
            ResponseMode = ProtoMapper.GetString(source.ResponseMode, source.HasResponseMode),
            Nonce = ProtoMapper.GetString(source.Nonce, source.HasNonce),
            Display = ProtoMapper.GetString(source.Display, source.HasDisplay),
            Prompt = ProtoMapper.GetString(source.Prompt, source.HasPrompt)?.Split(' ', StringSplitOptions.RemoveEmptyEntries),
            MaxAge = source.MaxAge?.ToTimeSpan(),
            UiLocales = source.UiLocales.GetArray(name => new CultureInfo(name)),
            ClaimsLocales = source.ClaimsLocales.GetArray(name => new CultureInfo(name)),
            IdTokenHint = ProtoMapper.GetString(source.IdTokenHint, source.HasIdTokenHint),
            LoginHint = ProtoMapper.GetString(source.LoginHint, source.HasLoginHint),
            AcrValues = source.AcrValues.GetArray(),
            CodeChallenge = ProtoMapper.GetString(source.CodeChallenge, source.HasCodeChallenge),
            CodeChallengeMethod = ProtoMapper.GetString(source.CodeChallengeMethod, source.HasCodeChallengeMethod),
            Request = ProtoMapper.GetString(source.Request, source.HasRequest),
            RequestUri = ProtoMapper.GetUri(source.RequestUri, source.HasRequestUri),
            Resources = source.Resources.GetArray(r => new Uri(r)),
            ProofKeyThumbprint = ProtoMapper.GetString(source.ProofKeyThumbprint, source.HasProofKeyThumbprint),
            AuthorizationDetails = source.HasAuthorizationDetailsJson
                ? JsonNode.Parse(source.AuthorizationDetailsJson) as JsonArray
                : null,
            PromptedAt = source.PromptedAt?.ToDateTimeOffset(),
            OriginRequestUri = ProtoMapper.GetUri(source.OriginRequestUri, source.HasOriginRequestUri),
        };
    }
}
