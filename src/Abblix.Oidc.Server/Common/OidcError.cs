// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// Represents an error that occurred during OAuth 2.0/OpenID Connect request processing.
/// </summary>
/// <param name="Error">The error code indicating the nature of the error.</param>
/// <param name="ErrorDescription">A human-readable description of the error.</param>
public record OidcError(string Error, string ErrorDescription)
{
    /// <summary>
    /// A human-readable description of the error, made only of the characters RFC 6749 allows in it.
    /// </summary>
    /// <remarks>
    /// The replacement is made where the error is built rather than in each refusal, since a description often
    /// quotes what the client sent. <see cref="Endpoints.Authorization.Interfaces.AuthorizationError"/>, which an
    /// authorization response is also built as directly, does the same.
    /// </remarks>
    public string ErrorDescription { get; init => field = OAuthErrorDescription.Sanitize(value); } =
        OAuthErrorDescription.Sanitize(ErrorDescription);

    /// <summary>
    /// The DPoP proof signature algorithms the profile of the client the refused token was issued to admits, which a
    /// <c>WWW-Authenticate: DPoP</c> challenge answering the refusal advertises (RFC 9449 section 7.1); empty where
    /// that profile refuses DPoP, null where the client is not known.
    /// </summary>
    public IReadOnlyCollection<string>? DPoPAlgorithmsAdmitted { get; init; }

    /// <summary>
    /// The scheme the refused request presented its access token with, whose challenge carries the error where the
    /// response advertises both DPoP and Bearer (RFC 9449 section 7.2); null where it could not be established, and
    /// then both challenges carry it.
    /// </summary>
    public AccessTokenScheme? PresentedScheme { get; init; }

    /// <summary>
    /// The scope the request needs, which a challenge answering an <c>insufficient_scope</c> refusal names in its
    /// <c>scope</c> attribute (RFC 6750 section 3.1); null where the refusal names none.
    /// </summary>
    public string? RequiredScope { get; init; }
}
