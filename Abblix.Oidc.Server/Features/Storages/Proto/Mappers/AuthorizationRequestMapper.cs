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

using System.Globalization;
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

        if (source.ClientId != null) proto.ClientId = source.ClientId;
        if (source.RedirectUri != null) proto.RedirectUri = source.RedirectUri.ToString();
        if (source.State != null) proto.State = source.State;
        if (source.ResponseMode != null) proto.ResponseMode = source.ResponseMode;
        if (source.Nonce != null) proto.Nonce = source.Nonce;
        if (source.Display != null) proto.Display = source.Display;
        if (source.Prompt != null) proto.Prompt = source.Prompt;
        if (source.IdTokenHint != null) proto.IdTokenHint = source.IdTokenHint;
        if (source.LoginHint != null) proto.LoginHint = source.LoginHint;
        if (source.CodeChallenge != null) proto.CodeChallenge = source.CodeChallenge;
        if (source.CodeChallengeMethod != null) proto.CodeChallengeMethod = source.CodeChallengeMethod;
        if (source.Request != null) proto.Request = source.Request;
        if (source.RequestUri != null) proto.RequestUri = source.RequestUri.ToString();

        if (source.MaxAge.HasValue)
            proto.MaxAge = Duration.FromTimeSpan(source.MaxAge.Value);

        proto.UiLocales.AddIfNotNull(source.UiLocales, c => c.Name);
        proto.ClaimsLocales.AddIfNotNull(source.ClaimsLocales, c => c.Name);
        proto.Resources.AddIfNotNull(source.Resources, u => u.OriginalString);

        return proto;
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
            Prompt = ProtoMapper.GetString(source.Prompt, source.HasPrompt),
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
        };
    }
}
