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

import java.util.ArrayList;
import java.util.List;

import org.eclipse.californium.elements.util.StringUtil;

/**
 * Reassemble fragmented handshake messages.
 * 
 * According
 * <a href="https://datatracker.ietf.org/doc/rfc6347#section-4.2.3">RFC 6347,
 * Section 4.2.3</a> "DTLS implementations MUST be able to handle overlapping
 * fragment ranges". Therefore the processing of overlapping fragments is
 * optimized by early testing, if it contains a new data-range and merging of
 * adjacent ranges afterwards.
 */
public final class ReassemblingHandshakeMessage extends HandshakeMessage {

	/** The reassembled fragments handshake body. */
	private final byte[] reassembledBytes;

	/** The handshake message's type. */
	private final HandshakeType type;

	/** The list of fragment ranges. */
	private final List<FragmentRange> fragments = new ArrayList<>();

	private static class FragmentRange {

		private int offset;
		private int length;
		private int end;

		private FragmentRange(int offset, int length) {
			this.offset = offset;
			this.length = length;
			this.end = offset + length;
		}

		/**
		 * Amend end.
		 * 
		 * @param end new higher end. Same or lower end is ignored.
		 */
		private void amendEnd(int end) {
			if (this.end < end) {
				this.end = end;
				this.length = this.end - this.offset;
			}
		}

		@Override
		public String toString() {
			return String.format("range[%d:%d)", offset, end);
		}
	}

	/**
	 * Called when reassembling a handshake message or received a fragment
	 * during the handshake.
	 * 
	 * @param message starting fragmented message
	 */
	public ReassemblingHandshakeMessage(FragmentedHandshakeMessage message) {
		super(message.getPeer());
		setMessageSeq(message.getMessageSeq());
		this.type = message.getMessageType();
		this.reassembledBytes = new byte[message.getMessageLength()];
		add(0, new FragmentRange(message.getFragmentOffset(), message.getFragmentLength()), message);
	}

	/**
	 * Check, if message reassembling is complete.
	 * 
	 * @return {@code true}, if message is complete
	 */
	public boolean isComplete() {
		// check, if first range is from 0 to message length
		FragmentRange firstRange = fragments.get(0);
		return firstRange.offset == 0 && getMessageLength() <= firstRange.end;
	}

	/**
	 * Add data of fragment to reassembled data.
	 * 
	 * Optimize processing of overlapping fragments by early testing, if it
	 * contains a new data-range and merging of adjacent ranges before
	 * returning.
	 * 
	 * @param message fragmented handshake message
	 * @throws IllegalArgumentException if type, sequence number, total message
	 *             length, or peer's address doesn't match the previous
	 *             fragments. Or the fragment exceeds the handshake message.
	 */
	public void add(FragmentedHandshakeMessage message) {
		if (type != message.getMessageType()) {
			throw new IllegalArgumentException(
					"Fragment message type " + message.getMessageType() + " differs from " + type + "!");
		} else if (getMessageSeq() != message.getMessageSeq()) {
			throw new IllegalArgumentException("Fragment message sequence number " + message.getMessageSeq()
					+ " differs from " + getMessageSeq() + "!");
		} else if (getMessageLength() != message.getMessageLength()) {
			throw new IllegalArgumentException("Fragment message length " + message.getMessageLength()
					+ " differs from " + getMessageLength() + "!");
		} else if (!getPeer().equals(message.getPeer())) {
			throw new IllegalArgumentException(
					"Fragment message peer " + message.getPeer() + " differs from " + getPeer() + "!");
		}
		if (isComplete()) {
			return;
		}

		FragmentRange newRange = new FragmentRange(message.getFragmentOffset(), message.getFragmentLength());
		if (getMessageLength() < newRange.end) {
			throw new IllegalArgumentException(
					"Fragment message " + newRange.end + " bytes exceeds message " + getMessageLength() + " bytes!");
		}
		// find range position
		int position = 0;
		for (; position < fragments.size(); ++position) {
			FragmentRange currentRange = fragments.get(position);
			if (newRange.offset <= currentRange.offset) {
				// we find the position
				break;
			} else if (newRange.end <= currentRange.end) {
				// overlap, already assembled
				return;
			}
		}
		// add new data
		add(position, newRange, message);
		// try to merge adjacent ranges
		FragmentRange currentRange = fragments.get(0);
		for (position = 1; position < fragments.size(); ++position) {
			FragmentRange nextRange = fragments.get(position);
			if (nextRange.offset <= currentRange.end) {
				// check for overlap [cur [new cur) new)
				// merge range to [cur new)
				currentRange.amendEnd(nextRange.end);
				fragments.remove(position);
				--position;
			} else {
				currentRange = nextRange;
			}
		}
	}

	/**
	 * Add range and position and copy fragment
	 * 
	 * @param position position to add range
	 * @param range range to add
	 * @param message fragment to copy
	 * @see #fragments
	 * @see #reassembledBytes
	 */
	private void add(int position, FragmentRange range, FragmentedHandshakeMessage message) {
		fragments.add(position, range);
		System.arraycopy(message.fragmentToByteArray(), 0, reassembledBytes, range.offset, range.length);
	}

	@Override
	public HandshakeType getMessageType() {
		return type;
	}

	@Override
	public int getMessageLength() {
		return reassembledBytes.length;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("\tReassembled Handshake Protocol");
		sb.append(StringUtil.lineSeparator()).append("\tType: ").append(getMessageType());
		sb.append(StringUtil.lineSeparator()).append("\tPeer: ").append(getPeer());
		sb.append(StringUtil.lineSeparator()).append("\tMessage Sequence No: ").append(getMessageSeq());
		sb.append(StringUtil.lineSeparator()).append("\tFragment Offset: ").append(getFragmentOffset());
		sb.append(StringUtil.lineSeparator()).append("\tFragment Length: ").append(getFragmentLength());
		sb.append(StringUtil.lineSeparator()).append("\tLength: ").append(getMessageLength());
		sb.append(StringUtil.lineSeparator());

		return sb.toString();
	}

	@Override
	public byte[] fragmentToByteArray() {
		return reassembledBytes;
	}

	List<Object> getRanges() {
		return new ArrayList<Object>(fragments);
	}
}
