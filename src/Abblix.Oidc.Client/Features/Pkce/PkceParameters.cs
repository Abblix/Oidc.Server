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

namespace Abblix.Oidc.Client.Features.Pkce;

/// <summary>
/// The Proof Key for Code Exchange values of one authorization request, as defined by RFC 7636.
/// </summary>
/// <param name="CodeVerifier">
/// The secret half. Never leaves this client until the authorization code is exchanged, and is what proves
/// that the client redeeming the code is the one that asked for it.
/// </param>
/// <param name="CodeChallenge">
/// The public half, derived from the verifier and sent with the authorization request. Whoever intercepts it
/// cannot derive the verifier from it.
/// </param>
/// <param name="CodeChallengeMethod">
/// The transformation used to derive <paramref name="CodeChallenge"/> from the verifier.
/// </param>
public sealed record PkceParameters(string CodeVerifier, string CodeChallenge, string CodeChallengeMethod);
