package org.rabinfingerprint;

import java.io.File;


import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.rabinfingerprint.Args.ArgParseException;
import org.rabinfingerprint.fingerprint.RabinFingerprintLong;
import org.rabinfingerprint.handprint.BoundaryDetectors;
import org.rabinfingerprint.handprint.EnhancedFingerFactory;
import org.rabinfingerprint.handprint.Handprint;
import org.rabinfingerprint.handprint.Handprints;
import org.rabinfingerprint.handprint.EnhancedFingerFactory.EnhancedChunkVisitor;
import org.rabinfingerprint.handprint.FingerFactory.ChunkBoundaryDetector;
import org.rabinfingerprint.handprint.Handprints.HandPrintFactory;
import org.rabinfingerprint.polynomial.Polynomial;

import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import com.google.common.io.ByteStreams;

public class Main {

	public void fingerprintFiles(List<String> paths, Polynomial p) throws FileNotFoundException,
			IOException {
		final RabinFingerprintLong rabin = new RabinFingerprintLong(p);
		for (String path : paths) {
			File file = new File(path);
			if (file.exists()) {
				rabin.reset();
				rabin.pushBytes(ByteStreams.toByteArray(new FileInputStream(file)));
				System.out.println(String.format("%X %s", rabin.getFingerprintLong(), file.getAbsolutePath()));
				System.out.flush();
			} else {
				System.err.print(String.format("Could not find file %s", path));
				System.err.flush();
			}
		}
	}

	public void fingerprintStdin(Polynomial p) throws IOException {
		final RabinFingerprintLong rabin = new RabinFingerprintLong(p);
		rabin.pushBytes(ByteStreams.toByteArray(System.in));
		System.out.println(String.format("%X", rabin.getFingerprintLong()));
	}

	public void handprintStdin(Polynomial p) throws IOException {
		HandPrintFactory factory = Handprints.newFactory(p);
		Handprint hand = factory.newHandprint(System.in);
		for (Long finger : hand.getHandFingers().keySet()) {
			System.out.println(String.format("%X", finger));
		}
	}

	public void handprintFiles(List<String> paths, Polynomial p) throws IOException {
		HandPrintFactory factory = Handprints.newFactory(p);
		for (String path : paths) {
			File file = new File(path);
			if (file.exists()) {
				Handprint hand = factory.newHandprint(new FileInputStream(file));
				for (Long finger : hand.getHandFingers().keySet()) {
					System.out.println(String.format("%X", finger));
				}
				System.out.flush();
			} else {
				System.err.print(String.format("Could not find file %s", path));
				System.err.flush();
			}
		}
	}

	public void generatePolynomial(int deg) {
		Polynomial p = Polynomial.createIrreducible(deg);
		System.out.println(p.toHexString());
	}

	public void printUsage() throws IOException {
		ByteStreams.copy(getClass().getResourceAsStream("/usage.txt"), System.out);
	}

	public Polynomial checkPolynomial(Long l) throws ArgParseException {
		Polynomial p = Polynomial.createFromLong(l);
		if (p.isReducible()) {
			throw new ArgParseException(
					"The specified polynomial is not irreducible and therefore invalid for the rabin fingerprint method. Please use -polygen to generate an irreducible polynomial.");
		}
		return p;
	}
	/*
	private ArgsModel model;

	private Main(ArgsModel model) {
		this.model = model;
	}

	
	private void run() throws Exception {
		switch (model.mode) {
		case FINGERPRINT:
			if (model.inputModel == InputMode.STDIN) {
				fingerprintStdin(checkPolynomial(model.polynomial));
			} else {
				fingerprintFiles(model.unflagged, checkPolynomial(model.polynomial));
			}
			break;
		case HANDPRINT:
			if (model.inputModel == InputMode.STDIN) {
				handprintStdin(checkPolynomial(model.polynomial));
			} else {
				handprintFiles(model.unflagged, checkPolynomial(model.polynomial));
			}
			break;
		case HELP:
			printUsage();
			break;
		case POLYGEN:
			generatePolynomial(model.degree);
			break;
		}
	}
	*/
	static final long bytesPerWindow = 48;
	static Polynomial p = Polynomial.createFromLong(10923124345206883L);
	public static void main(String[] args) {
		try {
			Random rnd = new Random();
			byte [] k = new byte[256*1024+5];
			rnd.nextBytes(k);
			ChunkBoundaryDetector boundaryDetector = BoundaryDetectors.DEFAULT_BOUNDARY_DETECTOR;
			EnhancedFingerFactory ff =new EnhancedFingerFactory(p, bytesPerWindow,
					boundaryDetector, 4096, 256*1024);
			int runs =10000;
			long tm = System.currentTimeMillis();
			final HashFunction hf = Hashing.sha256();
			byte [] hb =hf.hashBytes(k).asBytes();
			final ByteBuffer bf = ByteBuffer.wrap(new byte[k.length]);
			for(int i = 0;i<runs;i++) {
				ff.getChunkFingerprints(k, new EnhancedChunkVisitor() {
					public void visit(long fingerprint, long chunkStart, long chunkEnd,
							byte[] chunk) {
								bf.position((int)chunkStart);
								bf.put(chunk);
								hf.hashBytes(chunk).asBytes();
								
						}
				 });
			}
			byte[] nhb = hf.hashBytes(bf.array()).asBytes();
			if(!Arrays.equals(hb, nhb))
				System.out.println("noooo");
			long dur = (System.currentTimeMillis() - tm)/1000;
			long kb = ((long)k.length * (long)runs)/(1024*1024);
			double mbps = ((double)kb/dur);
			System.out.println("mbs=" +mbps + " dur=" + dur);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
		System.exit(0);
	}
}
