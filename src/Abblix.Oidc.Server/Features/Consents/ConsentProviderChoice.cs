// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Consents;

/// <summary>
/// Records whether the host chose how end-user consent is obtained, so the choice is checked at startup rather than
/// on the first authorization request: it registered its own <see cref="IUserConsentsProvider"/>, or granted every
/// client everything it asks for by calling
/// <see cref="ConsentsServiceCollectionExtensions.AddConsentGrantedForEveryClient"/>.
/// </summary>
/// <remarks>
/// Riding the options-validation pipeline is what buys the timing: <c>ValidateOnStart</c> registers a startup
/// validator, and the host runs it before it starts the hosted service that opens the HTTP port, so a server that
/// never obtains consent does not serve a request. The check has options of its own rather than riding those of
/// the server, because the server's options are read by code running with no host lifetime at all, which would
/// meet the refusal on its first read instead of at startup.
/// </remarks>
public sealed class ConsentProviderChoice
{
	/// <summary>
	/// Whether the container holds an <see cref="IUserConsentsProvider"/>, read from the container rather than from
	/// the registrations the server saw, because a host registers its provider after the server's own registration as
	/// often as before it.
	/// </summary>
	public bool ProviderRegistered { get; set; }
}
