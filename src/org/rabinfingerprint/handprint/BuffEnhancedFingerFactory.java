package org.rabinfingerprint.handprint;

import java.io.IOException;
import java.nio.ByteBuffer;

import org.rabinfingerprint.fingerprint.BufRabinFingerprintLongWindowedOptimized;
import org.rabinfingerprint.fingerprint.RabinFingerprintLongWindowed;
import org.rabinfingerprint.handprint.FingerFactory.ChunkBoundaryDetector;
import org.rabinfingerprint.polynomial.Polynomial;

public class BuffEnhancedFingerFactory {

	private final RabinFingerprintLongWindowed fingerWindow;
	private final ChunkBoundaryDetector boundaryDetector;
	private int MIN_CHUNK_SIZE = 4096;
	private int MAX_CHUNK_SIZE = 1024 * 1024;

	public BuffEnhancedFingerFactory(Polynomial p, long bytesPerWindow, ChunkBoundaryDetector boundaryDetector) {
		this.fingerWindow = new RabinFingerprintLongWindowed(p, bytesPerWindow);
		this.boundaryDetector = boundaryDetector;
	}

	public BuffEnhancedFingerFactory(Polynomial p, long bytesPerWindow, ChunkBoundaryDetector boundaryDetector,
			int minChunkSize, int maxChunkSize) {
		this.fingerWindow = new RabinFingerprintLongWindowed(p, bytesPerWindow);
		this.boundaryDetector = boundaryDetector;
		this.MIN_CHUNK_SIZE = minChunkSize;
		this.MAX_CHUNK_SIZE = maxChunkSize;

	}
	
	public BuffEnhancedFingerFactory(Polynomial p, long bytesPerWindow, ChunkBoundaryDetector boundaryDetector,
			int minChunkSize, int maxChunkSize,boolean b) {
		this.fingerWindow = new RabinFingerprintLongWindowed(p, bytesPerWindow);
		this.boundaryDetector = boundaryDetector;
		this.MIN_CHUNK_SIZE = minChunkSize;
		this.MAX_CHUNK_SIZE = maxChunkSize;

	}

	public static interface EnhancedChunkVisitor {
		public void visit(long fingerprint, long chunkStart, long chunkEnd, byte[] chunk);
	}
	
	
	public void getChunkFingerprints(ByteBuffer k, EnhancedChunkVisitor visitor) throws IOException {
		// windowing fingerprinter for finding chunk boundaries. this is only
		// reset at the beginning of the file
		k.position(0);
		if(k.capacity() <= (MIN_CHUNK_SIZE+1)) {
			byte [] b = new byte[k.capacity()];
			k.get(b);
			visitor.visit(0, 0, b.length, b);
		}
		BufRabinFingerprintLongWindowedOptimized window = new BufRabinFingerprintLongWindowedOptimized(fingerWindow,k,0);
		// counters
		int chunkStart = 0;
		int chunkEnd = 0;
		int chunkLength = 0;
		/*
		 * fingerprint one byte at a time. we have to use this granularity to
		 * ensure that, for example, a one byte offset at the beginning of the
		 * file won't effect the chunk boundaries
		 */
		int cl = k.capacity();
		while (chunkEnd < cl) {
			// push byte into fingerprints

			/*
			 * if we've reached a boundary (which we will at some probability
			 * based on the boundary pattern and the size of the fingerprint
			 * window), we store the current chunk fingerprint and reset the
			 * chunk fingerprinter.
			 */
			if (chunkLength == 0) {
				chunkLength = MIN_CHUNK_SIZE;
				int rem = cl - chunkEnd;
				if (rem < chunkLength) {
					chunkLength = rem;
				}
				chunkEnd += chunkLength;
				window.setStart(chunkEnd);
				window.reset();
			} else if (chunkLength > MIN_CHUNK_SIZE && boundaryDetector.isBoundary(window)) {
				byte[] c = new byte[chunkLength];
				k.get(c, chunkStart, chunkLength);
				visitor.visit(0, chunkStart, chunkEnd, c);
				chunkStart = chunkEnd;
				chunkLength = 0;
			} else if (chunkLength >= MAX_CHUNK_SIZE) {
				byte[] c = new byte[chunkLength];
				k.get(c, chunkStart, chunkLength);
				visitor.visit(0, chunkStart, chunkEnd, c);
				// store last chunk offset
				chunkStart = chunkEnd;
				chunkLength = 0;
			} else {
				window.pushByte(chunkEnd);
				chunkEnd++;
				chunkLength++;
			}
		}
		if (chunkLength > 0) {
			byte[] c = new byte[chunkLength];
			k.get(c, chunkStart, chunkLength);
			visitor.visit(0, chunkStart, chunkEnd, c);
		}
	}
}