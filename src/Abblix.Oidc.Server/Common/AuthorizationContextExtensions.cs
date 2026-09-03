// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Abblix.Jwt;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// Provides extension methods for working with <see cref="AuthorizationContext"/> objects,
/// facilitating the conversion between authorization contexts and JWT claims.
/// </summary>
public static class AuthorizationContextExtensions
{
    private static readonly JsonSerializerOptions JsonSerializerOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>
    /// Names the given resource as the audience when the context names none, so a token says which party is
    /// meant to consume it rather than which one asked for it.
    /// </summary>
    /// <param name="context">The authorization context to complete.</param>
    /// <param name="defaultResource">The resource to fall back on, or <c>null</c> to leave the context alone.</param>
    /// <returns>The context, with the default resource applied where it was needed.</returns>
    /// <remarks>
    /// RFC 9068 Section 3: "If the request does not include a `resource` parameter, the authorization server
    /// MUST use a default resource indicator in the `aud` claim." With no default supplied the context is
    /// returned untouched and the audience later falls back to the issuer (see <see cref="ApplyTo"/>) - the
    /// behaviour changes only where a host states the default, because that value is read by every resource
    /// server in the deployment.
    /// A context that already names a resource or an audience is returned unchanged: it says who the token is
    /// for, and this only fills a gap.
    /// </remarks>
    public static AuthorizationContext WithDefaultResource(
        this AuthorizationContext context,
        Uri? defaultResource)
    {
        if (defaultResource is null)
            return context;

        if (context.Resources is { Length: > 0 } || context.Audiences is { Length: > 0 })
            return context;

        return context with { Resources = [defaultResource] };
    }

    /// <summary>
    /// Applies the information from an <see cref="AuthorizationContext"/> to a <see cref="JsonWebTokenPayload"/>,
    /// converting the context into JWT claims.
    /// </summary>
    /// <param name="context">The <see cref="AuthorizationContext"/> containing authorization details.</param>
    /// <param name="payload">The JWT payload where the authorization context information will be applied as claims.</param>
    /// <remarks>
    /// This method is useful for embedding authorization details directly into a JWT, allowing for efficient transfer
    /// and validation of authorization information.
    /// </remarks>
    public static void ApplyTo(this AuthorizationContext context, JsonWebTokenPayload payload)
    {
        payload.ClientId = context.ClientId;
        payload.Scope = context.Scope;
        payload.Nonce = context.Nonce;

        // RFC 8707 Resources (absolute URIs) + RFC 8693 section 2.1 Audiences (opaque logical names) both feed
        // into the JWT aud claim. Resources take precedence in ordering for legacy compat.
        //
        // With neither set, the audience is the issuer. RFC 9068 section 3 requires a default resource
        // indicator here, and section 4 tells a resource server to reject a token whose aud does not name it -
        // so the client id, which names the party that asked for the token rather than the one that
        // reads it, is a value a conforming resource server must refuse. Where nothing was requested
        // the consumer is this server, and the issuer identifies it exactly, without a host having to
        // invent a URI for a resource that does not exist.
        //
        // The issuer is read off the payload rather than taken as a parameter: every caller sets it
        // before calling this, and threading it through would change a shipped public signature.
        var audienceParts = new List<string>();
        if (context.Resources is { Length: > 0 })
            audienceParts.AddRange(Array.ConvertAll(context.Resources, res => res.OriginalString));
        if (context.Audiences is { Length: > 0 })
            audienceParts.AddRange(context.Audiences);
        payload.Audiences = audienceParts.Count > 0
            ? audienceParts.ToArray()
            : [payload.Issuer.NotNull(nameof(payload.Issuer))];

        payload[JwtClaimTypes.RequestedClaims] = JsonSerializer.SerializeToNode(
            context.RequestedClaims,
            JsonSerializerOptions);

        // mTLS (RFC 8705) and DPoP (RFC 9449) can coexist on a single token; when both
        // bindings are present the cnf object carries x5t#S256 and jkt side by side.
        // When neither binding is present, no cnf claim is emitted.
        if (!string.IsNullOrWhiteSpace(context.CertificateSha256Thumbprint) ||
            !string.IsNullOrWhiteSpace(context.ProofKeyThumbprint))
        {
            payload.Confirmation = new JsonWebTokenConfirmation
            {
                CertificateSha256Thumbprint = context.CertificateSha256Thumbprint,
                JwkThumbprint = context.ProofKeyThumbprint,
            };
        }

        // RFC 9396 section 9: the AS MAY include the authorized authorization_details in the access
        // token. We do, copying the raw JsonArray byte-exact so member order and type-specific
        // payload are preserved without typed deserialise/re-serialise cycles. DeepClone keeps
        // the payload's JsonNode tree independent of the source AuthorizationContext.
        if (context.AuthorizationDetails is { Count: > 0 })
        {
            payload.Json[IanaClaimTypes.AuthorizationDetails] = context.AuthorizationDetails.DeepClone();
        }

        // RFC 8693 section 4.1: emit the act claim for delegation tokens. Nested act chains live in
        // the JsonObject's act member -- preserved byte-exact via DeepClone.
        if (context.Actor is not null)
        {
            payload.Json[IanaClaimTypes.Act] = context.Actor.DeepClone();
        }
    }

    /// <summary>
    /// Creates an <see cref="AuthorizationContext"/> from a <see cref="JsonWebTokenPayload"/>,
    /// converting JWT claims back into an authorization context.
    /// </summary>
    /// <param name="payload">The JWT payload containing claims that represent an authorization context.</param>
    /// <returns>An instance of <see cref="AuthorizationContext"/> populated with information derived from
    /// the JWT claims.</returns>
    /// <remarks>
    /// This method facilitates the extraction of authorization details from JWT claims,
    /// reconstructing an <see cref="AuthorizationContext"/> for further processing or validation.
    /// </remarks>
    public static AuthorizationContext ToAuthorizationContext(this JsonWebTokenPayload payload)
    {
        var audiences = payload.Audiences.ToArray();

        // A lone audience naming this server, or the client that asked for the token, is what the write side
        // puts there when the request named no resource - so reading it back must not produce a resource
        // nobody requested, or a refresh would silently narrow the new token to it. The client identifier is
        // still recognised here because tokens issued before the fallback became the issuer name the client,
        // and they stay valid until they expire.
        Uri[]? resources = null;
        if (audiences.Length != 1 || (audiences[0] != payload.Issuer && audiences[0] != payload.ClientId))
        {
            resources = audiences
                .Select(aud => Uri.TryCreate(aud, UriKind.Absolute, out var uri) ? uri : null)
                .OfType<Uri>()
                .ToArray();
        }

        var cnf = payload.Confirmation;

        return new AuthorizationContext(
            payload.ClientId.NotNull(nameof(payload.ClientId)),
            payload.Scope.NotNull(nameof(payload.Scope)).ToArray(),
            payload[JwtClaimTypes.RequestedClaims].Deserialize<RequestedClaims>(JsonSerializerOptions),
            resources)
        {
            Nonce = payload.Nonce,
            CertificateSha256Thumbprint = cnf?.CertificateSha256Thumbprint,
            ProofKeyThumbprint = cnf?.JwkThumbprint,
            AuthorizationDetails = payload.Json[IanaClaimTypes.AuthorizationDetails] is JsonArray raw
                ? (JsonArray)raw.DeepClone()
                : null,
            Actor = payload.Json[IanaClaimTypes.Act] is JsonObject act
                ? (JsonObject)act.DeepClone()
                : null,
        };
    }
}
