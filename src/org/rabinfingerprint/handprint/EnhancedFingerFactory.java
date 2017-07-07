package org.rabinfingerprint.handprint;

import java.io.IOException;



import org.rabinfingerprint.fingerprint.RabinFingerprintLongWindowed;
import org.rabinfingerprint.fingerprint.RabinFingerprintLongWindowedOptimized;
import org.rabinfingerprint.handprint.FingerFactory.ChunkBoundaryDetector;
import org.rabinfingerprint.polynomial.Polynomial;

public class EnhancedFingerFactory {

	private final RabinFingerprintLongWindowed fingerWindow;
	private final ChunkBoundaryDetector boundaryDetector;
	private int MIN_CHUNK_SIZE = 4096;
	private int MAX_CHUNK_SIZE = 1024 * 1024;

	public EnhancedFingerFactory(Polynomial p, long bytesPerWindow, ChunkBoundaryDetector boundaryDetector) {
		this.fingerWindow = new RabinFingerprintLongWindowed(p, bytesPerWindow);
		this.boundaryDetector = boundaryDetector;
	}

	public EnhancedFingerFactory(Polynomial p, long bytesPerWindow, ChunkBoundaryDetector boundaryDetector,
			int minChunkSize, int maxChunkSize) {
		this.fingerWindow = new RabinFingerprintLongWindowed(p, bytesPerWindow);
		this.boundaryDetector = boundaryDetector;
		this.MIN_CHUNK_SIZE = minChunkSize;
		this.MAX_CHUNK_SIZE = maxChunkSize;

	}
	
	public EnhancedFingerFactory(Polynomial p, long bytesPerWindow, ChunkBoundaryDetector boundaryDetector,
			int minChunkSize, int maxChunkSize,boolean b) {
		this.fingerWindow = new RabinFingerprintLongWindowed(p, bytesPerWindow);
		this.boundaryDetector = boundaryDetector;
		this.MIN_CHUNK_SIZE = minChunkSize;
		this.MAX_CHUNK_SIZE = maxChunkSize;

	}

	public static interface EnhancedChunkVisitor {
		public void visit(long fingerprint, long chunkStart, long chunkEnd, byte[] chunk);
	}
	
	
	public void getChunkFingerprints(byte[] k, EnhancedChunkVisitor visitor) throws IOException {
		// windowing fingerprinter for finding chunk boundaries. this is only
		// reset at the beginning of the file
		if(k.length <= (MIN_CHUNK_SIZE+1)) {
			visitor.visit(0, 0, k.length, k);
		}
		RabinFingerprintLongWindowedOptimized window = new RabinFingerprintLongWindowedOptimized(fingerWindow,k,0);
		// counters
		int chunkStart = 0;
		int chunkEnd = 0;
		int chunkLength = 0;
		/*
		 * fingerprint one byte at a time. we have to use this granularity to
		 * ensure that, for example, a one byte offset at the beginning of the
		 * file won't effect the chunk boundaries
		 */
		int cl = k.length;
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
				System.arraycopy(k, chunkStart, c, 0, chunkLength);
				visitor.visit(0, chunkStart, chunkEnd, c);
				chunkStart = chunkEnd;
				chunkLength = 0;
			} else if (chunkLength >= MAX_CHUNK_SIZE) {
				byte[] c = new byte[chunkLength];
				System.arraycopy(k, chunkStart, c, 0, chunkLength);
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
			System.arraycopy(k, chunkStart, c, 0, chunkLength);
			visitor.visit(0, chunkStart, chunkEnd, c);
		}
	}
}