// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt.Encryption;
using Xunit;

namespace Abblix.Jwt.UnitTests.Encryption;

/// <summary>
/// The test cases of RFC 7518 Appendix B, an answer computed outside this library: the content key, the initialization
/// vector and the associated data give exactly the ciphertext and tag listed there, and opening them gives back the
/// plaintext.
/// </summary>
public class AesCbcHmacKnownAnswerTests
{
	private const string Plaintext =
		"41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e"
		+ "64206974206d7573742062652061626c6520746f2066616c6c20696e746f207468652068616e6473206f662074686520656e656d79"
		+ "20776974686f757420696e636f6e76656e69656e6365";

	private const string InitializationVector = "1af38c2dc2b96ffdd86694092341bc04";

	private const string AdditionalAuthenticatedData =
		"546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673";

	public static TheoryData<string, string, string, string> AppendixB => new()
	{
		{
			EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256,
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			"c80edfa32ddf39d5ef00c0b468834279a2e46a1b8049f792f76bfe54b903a9c9a94ac9b47ad2655c5f10f9aef71427e2fc6f9b3f39"
			+ "9a221489f16362c703233609d45ac69864e3321cf82935ac4096c86e133314c54019e8ca7980dfa4b9cf1b384c486f3a54c51078"
			+ "158ee5d79de59fbd34d848b3d69550a67646344427ade54b8851ffb598f7f80074b9473c82e2db",
			"652c3fa36b0a7c5b3219fab3a30bc1c4"
		},
		{
			EncryptionAlgorithms.ContentEncryption.Aes192CbcHmacSha384,
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
			"ea65da6b59e61edb419be62d19712ae5d303eeb50052d0dfd6697f77224c8edb000d279bdc14c1072654bd30944230c657bed4ca0c"
			+ "9f4a8466f22b226d1746214bf8cfc2400add9f5126e479663fc90b3bed787a2f0ffcbf3904be2a641d5c2105bfe591bae23b1d74"
			+ "49e532eef60a9ac8bb6c6b01d35d49787bcd57ef484927f280adc91ac0c4e79c7b11efc60054e3",
			"8490ac0e58949bfe51875d733f93ac2075168039ccc733d7"
		},
		{
			EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512,
			"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435"
			+ "363738393a3b3c3d3e3f",
			"4affaaadb78c31c5da4b1b590d10ffbd3dd8d5d302423526912da037ecbcc7bd822c301dd67c373bccb584ad3e9279c2e6d12a1374"
			+ "b77f077553df829410446b36ebd97066296ae6427ea75c2e0846a11a09ccf5370dc80bfecbad28c73f09b3a3b75e662a2594410a"
			+ "e496b2e2e6609e31e6e02cc837f053d21f37ff4f51950bbe2638d09dd7a4930930806d0703b1f6",
			"4dd3b4c088a7f45c216839645b2012bf2e6269a8c56a816dbc1b267761955bc5"
		},
	};

	[Theory]
	[MemberData(nameof(AppendixB))]
	public void TheListedCiphertextAndTag_OpenToTheListedPlaintext(
		string algorithm, string key, string ciphertext, string tag)
	{
		var encryptor = new AesCbcHmacEncryptor(algorithm);

		var opened = encryptor.TryDecrypt(
			Convert.FromHexString(key),
			new EncryptedData(
				Convert.FromHexString(InitializationVector),
				Convert.FromHexString(ciphertext),
				Convert.FromHexString(tag)),
			Convert.FromHexString(AdditionalAuthenticatedData),
			out var plaintext);

		Assert.True(opened);
		Assert.Equal(Plaintext, Convert.ToHexStringLower(plaintext!));
	}

	[Theory]
	[MemberData(nameof(AppendixB))]
	public void TheListedInputs_GiveTheListedTag(string algorithm, string key, string ciphertext, string tag)
	{
		var contentKey = new AesCbcHmacKey(algorithm);
		var (macKey, _) = contentKey.Split(Convert.FromHexString(key));

		var computed = contentKey.TagOf(
			macKey,
			Convert.FromHexString(AdditionalAuthenticatedData),
			Convert.FromHexString(InitializationVector),
			Convert.FromHexString(ciphertext));

		Assert.Equal(tag, Convert.ToHexStringLower(computed));
	}
}
