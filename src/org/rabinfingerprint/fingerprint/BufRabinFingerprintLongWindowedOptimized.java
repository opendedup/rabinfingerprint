package org.rabinfingerprint.fingerprint;




import java.nio.ByteBuffer;

import org.rabinfingerprint.fingerprint.Fingerprint.WindowedFingerprint;
import org.rabinfingerprint.polynomial.Polynomial;

public class BufRabinFingerprintLongWindowedOptimized extends RabinFingerprintLong implements WindowedFingerprint<Polynomial> {

	protected final int bytesPerWindow;
	protected int startPos;
	protected final long[] popTable;
	ByteBuffer chunk;
	

	public BufRabinFingerprintLongWindowedOptimized(RabinFingerprintLongWindowed that, ByteBuffer chunk, int startPos) {
		super(that);
		this.chunk = chunk;
		this.bytesPerWindow = (int)that.bytesPerWindow;
		this.popTable = that.popTable;
		this.startPos = startPos;
	}

	
	@Override
	public void pushBytes(final byte[] bytes) {
	}

	@Override
	public void pushBytes(final byte[] bytes, final int offset, final int length) {
	}

	@Override
	public void pushByte(byte b) {
	}
	int spos = 0;
	int ep = 0;
	public void pushByte(int pos) {
		if(spos == 0)
			spos = pos;
		ep = pos;
		byte b = chunk.get(pos);
		int j = (int) ((fingerprint >> shift) & 0x1FF);
		fingerprint = ((fingerprint << 8) | (b & 0xFF)) ^ pushTable[j];
		int wp = pos-startPos;
		if(wp >=bytesPerWindow) {
			byte k = chunk.get(pos-bytesPerWindow);
			fingerprint ^= popTable[(k & 0xFF)];
		}
	}
	
	public void setStart(int pos) {
		this.startPos = pos;
	}

	/**
	 * Removes the contribution of the first byte in the byte queue from the
	 * fingerprint.
	 * 
	 * {@link RabinFingerprintPolynomial#popByte}
	 */
	public void popByte() {
	}

	@Override
	public void reset() {
		spos = 0;
		super.reset();
	}
}
