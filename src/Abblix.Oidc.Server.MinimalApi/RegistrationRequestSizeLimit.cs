// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.AspNetCore.Http.Metadata;

namespace Abblix.Oidc.Server.MinimalApi;

/// <summary>
/// Bounds the registration body at <see cref="OidcOptions.MaxRegistrationRequestSize"/>, as endpoint metadata
/// the server reads before it reads the body.
/// </summary>
/// <remarks>
/// The registration endpoint parses a foreign document and keeps the members it does not model, which costs
/// several times the body's own size in memory. Model binding runs ahead of every validator, including the
/// initial access token check, so nothing inside the pipeline is early enough to bound it - and an endpoint
/// filter, which runs after binding, would refuse a request whose cost has already been paid. Metadata is the
/// one hook the server consults first.
/// </remarks>
/// <param name="MaxRequestBodySize">The largest body the server will read, in bytes.</param>
internal sealed record RegistrationRequestSizeLimit(long? MaxRequestBodySize) : IRequestSizeLimitMetadata;
