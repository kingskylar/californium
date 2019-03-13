/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 *
 * Contributors:
 *    Bosch Software Innovations GmbH - initial API and implementation
 *******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.eclipse.californium.elements.util.StandardCharsets.UTF_8;

import java.util.Arrays;

import org.eclipse.californium.elements.auth.PreSharedKeyIdentity;
import org.eclipse.californium.elements.util.Bytes;

/**
 * Implementation of byte array based PSK public information (hint or identity).
 * 
 * Note: <a "https://tools.ietf.org/html/rfc4279#section-5.1">RFC 4279, Section
 * 5.1</a> defines to use UTF-8 to encode the identities. However, some peers
 * seems to use non UTF-8 identities. This byte array based implementation
 * allows to support such non-compliant clients. Though the string base identity
 * is used for {@link PreSharedKeyIdentity}, it's required to use
 * {@link #PskPublicInformation(String, byte[])} to setup a proper name for such
 * non-compliant peers in the
 * {@link org.eclipse.californium.scandium.dtls.pskstore.BytesPskStore}. During
 * the lookup of the secret key in the handshake, such a non-compliant identity
 * is normalized with the identity provided by the store.
 */
public final class PskPublicInformation extends Bytes {

	public static final PskPublicInformation EMPTY = new PskPublicInformation("");

	private static final int MAX_LENGTH = 65535;

	private final boolean utf8Compliant;

	private String publicInfo;

	/**
	 * Create PSK identity from bytes.
	 * 
	 * @param identityBytes PSK identity as bytes
	 * @throws NullPointerException if identity is {@code null}
	 * @throws IllegalArgumentException if identity length is larger than 255
	 */
	public PskPublicInformation(byte[] identityBytes) {
		this(new String(identityBytes, UTF_8), identityBytes);
	}

	public PskPublicInformation(String identity) {
		super(identity.getBytes(UTF_8), MAX_LENGTH, false);
		this.publicInfo = identity;
		this.utf8Compliant = true;
	}

	public PskPublicInformation(String identity, byte[] identityBytes) {
		super(identityBytes, MAX_LENGTH, false);
		this.publicInfo = identity;
		this.utf8Compliant = Arrays.equals(identityBytes, identity.getBytes(UTF_8));
	}

	public void normalize(String publicInfo) {
		if (utf8Compliant) {
			throw new IllegalArgumentException("Normalization not required for UTF-8!");
		}
		this.publicInfo = publicInfo;
	}

	public boolean startsWith(String start) {
		byte[] bytes = getBytes();
		byte[] startBytes = start.getBytes(UTF_8);
		if (bytes.length < startBytes.length) {
			return false;
		}
		for (int index = 0; index < startBytes.length; ++index) {
			if (bytes[index] != startBytes[index]) {
				return false;
			}
		}
		return true;
	}

	public boolean isUtf8Compliant() {
		return utf8Compliant;
	}

	public String getPublicInfoAsString() {
		return publicInfo;
	}

	@Override
	public String toString() {
		if (utf8Compliant) {
			return publicInfo;
		} else {
			return publicInfo + "/" + getAsString();
		}
	}
}
