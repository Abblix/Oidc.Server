// Abblix OIDC Client Library
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


namespace Abblix.Oidc.Client.Features.ProtectedResources;

/// <summary>
/// A token to present, and the scheme it is presented under.
/// </summary>
/// <remarks>
/// The scheme travels with the value rather than being assumed. RFC 6749 section 5.1 makes <c>token_type</c>
/// REQUIRED in a token response, and it says how the token is used: a bearer token goes in an
/// <c>Authorization: Bearer</c> header, while a sender-constrained one has to be accompanied by a proof.
/// Returning a bare string would decide that question here, for every source, forever.
/// </remarks>
/// <param name="Value">The token as the provider issued it.</param>
/// <param name="Scheme">The scheme from <see cref="Common.Constants.TokenTypes"/>.</param>
public sealed record AccessToken(string Value, string Scheme);
