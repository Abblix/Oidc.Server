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

using System.Text.Json.Nodes;

namespace Abblix.Jwt;

/// <summary>
/// Typed wrapper over the <c>cnf</c> confirmation-method JSON object (RFC 7800 §3.1).
/// Exposes the proof-of-possession binding members an issued JWT can carry: the mutual-TLS
/// client certificate thumbprint (<c>x5t#S256</c>, RFC 8705 §3.1) and the DPoP proof-key
/// JWK thumbprint (<c>jkt</c>, RFC 9449 §6.1). Symmetric with <see cref="JsonWebTokenPayload"/>:
/// each member is a typed accessor over the underlying <see cref="JsonObject"/>; constants
/// live in <see cref="IanaClaimTypes.ConfirmationMethods"/> so adding a new member is a
/// single-file edit.
/// </summary>
public class JsonWebTokenConfirmation(JsonObject json)
{
    /// <summary>
    /// Initialises a fresh, detached confirmation object backed by an empty
    /// <see cref="JsonObject"/>. Use this overload when constructing a new <c>cnf</c> for
    /// assignment to <see cref="JsonWebTokenPayload.Confirmation"/>; for read or
    /// read-modify-write paths obtain the wrapper from the payload instead.
    /// </summary>
    public JsonWebTokenConfirmation() : this(new JsonObject()) { }

    /// <summary>
    /// The underlying mutable JSON object backing the strongly-typed accessors. Exposed so
    /// the payload setter can attach this object as the <c>cnf</c> claim and so callers can
    /// read or write <c>cnf</c> members the wrapper does not yet expose as named properties.
    /// </summary>
    public JsonObject Json { get; } = json;

    /// <summary>
    /// Base64url-encoded SHA-256 thumbprint of the client X.509 certificate that
    /// authenticated the request (RFC 8705 §3.1). Locks an access token to the
    /// certificate the client presented at the token endpoint via mutual TLS.
    /// </summary>
    public string? CertificateSha256Thumbprint
    {
        get => Json.GetProperty<string>(IanaClaimTypes.ConfirmationMethods.CertificateSha256Thumbprint);
        set => Json.SetProperty(IanaClaimTypes.ConfirmationMethods.CertificateSha256Thumbprint, value);
    }

    /// <summary>
    /// Base64url-encoded RFC 7638 JWK Thumbprint of the DPoP proof key (RFC 9449 §6.1).
    /// Locks an access token to the specific proof-of-possession key the client
    /// demonstrated control of when the token was issued.
    /// </summary>
    public string? JwkThumbprint
    {
        get => Json.GetProperty<string>(IanaClaimTypes.ConfirmationMethods.JwkThumbprint);
        set => Json.SetProperty(IanaClaimTypes.ConfirmationMethods.JwkThumbprint, value);
    }
}
