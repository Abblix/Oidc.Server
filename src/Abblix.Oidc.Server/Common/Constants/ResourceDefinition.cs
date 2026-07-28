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

using Abblix.Jwt;

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// Represents a resource with associated scopes, defining the permissions and access levels within an application.
/// This record is typically used to configure and enforce authorization policies based on resource identifiers
/// and their corresponding scopes.
/// </summary>
/// <param name="Resource">The identifier for the resource, often a unique name or URL representing the resource.</param>
/// <param name="Scopes">A variable number of scope definitions associated with the resource. Each scope definition
/// specifies a scope and its related claims, detailing the access levels and permissions granted.</param>
public record ResourceDefinition(Uri Resource, params ScopeDefinition[] Scopes)
{
    /// <summary>
    /// The set of JSON Web Keys published by this resource server, used to encrypt an access token issued for
    /// it. Only public keys belong here: encryption uses the public half, and the resource keeps the private
    /// one (RFC 9728 Section 2 describes the same key set served over <see cref="JwksUri"/>).
    /// </summary>
    /// <remarks>
    /// Declaring a key is what asks for the access token to be encrypted to this resource rather than left a
    /// signed JWS. The key-management algorithm is taken from the key's own <c>alg</c> (RFC 7517 Section 4.4),
    /// so there is no separate algorithm declaration to keep in step: a key that declares none matches
    /// whatever the server offers.
    /// </remarks>
    public JsonWebKeySet? Jwks { get; init; }

    /// <summary>
    /// The URL where this resource server publishes its JSON Web Key Set, per
    /// <see href="https://datatracker.ietf.org/doc/html/rfc9728#section-2">RFC 9728 Section 2</see>. Fetched
    /// with the same SSRF-protected, cached path as a client's key set.
    /// </summary>
    /// <remarks>
    /// May be combined with <see cref="Jwks"/>, in which case the inline keys are considered first, exactly as
    /// for a client that registers both.
    /// </remarks>
    public Uri? JwksUri { get; init; }

    /// <summary>
    /// The identifiers of the registered clients this resource server authenticates as when it calls the
    /// introspection endpoint. A caller named here may introspect any token whose audience names this
    /// resource, even though the token was issued to somebody else.
    /// </summary>
    /// <remarks>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc7662#section-2.1">RFC 7662 Section 2.1</see> has
    /// the protected resource call introspection, and
    /// <see href="https://datatracker.ietf.org/doc/html/rfc7662#section-4">Section 4</see> states what the
    /// authorization server owes it: "determine whether or not the token can be used at the resource server
    /// making the introspection call." A resource server is by definition not the client the token was issued
    /// to, so without this list the only answer it could get is the active:false that
    /// <see href="https://datatracker.ietf.org/doc/html/rfc7662#section-2.2">Section 2.2</see> reserves for a
    /// token that does not exist or that the caller may not ask about.
    /// <para>
    /// This lives on the resource rather than on the client because resources are configured by the host
    /// alone. A client may not declare through dynamic registration which resource it speaks for, which would
    /// otherwise let it register a claim over somebody else's API and read every token issued for it.
    /// </para>
    /// Leaving it unset keeps the previous behaviour: only the client the token was issued to can introspect
    /// it.
    /// </remarks>
    public string[]? IntrospectionClientIds { get; init; }
}
