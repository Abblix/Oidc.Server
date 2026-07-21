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

using Abblix.Oidc.Client.Features.Authorization.Context;

namespace Abblix.Oidc.Client.Features.Authorization.Responses;

/// <summary>
/// A successful authorization response that has passed every check: an authorization code, and the
/// context of the login it belongs to.
/// </summary>
/// <remarks>
/// Handing back the context, not just the code, is deliberate. Redeeming the code needs the code
/// verifier and the exact redirect address the request used, and validating the resulting ID Token
/// needs the nonce - all of which were put aside when the request was built and none of which the
/// response carries. A caller given only the code would have to go looking for them.
/// That this exists at all means the checks passed: the issuer matched, the context was held and is now
/// consumed, the response was a code rather than an error. There is no partially-validated variant.
/// </remarks>
/// <param name="Code">The authorization code, to be exchanged at the token endpoint.</param>
/// <param name="Context">The context put aside when the request was built, now consumed.</param>
public sealed record AuthorizationCodeResult(string Code, AuthorizationContext Context);
