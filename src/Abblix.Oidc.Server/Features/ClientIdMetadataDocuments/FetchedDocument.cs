// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;

namespace Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;

/// <summary>
/// A client's metadata document as fetched, and how long its response allows it to be held.
/// </summary>
/// <param name="Content">The document, a JSON object.</param>
/// <param name="Lifetime">How long it may be held; zero when the response forbids holding it.</param>
internal sealed record FetchedDocument(JsonObject Content, TimeSpan Lifetime);
