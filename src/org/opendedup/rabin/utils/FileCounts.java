package org.opendedup.rabin.utils;

import java.io.File;
import java.io.IOException;



public class FileCounts {

	public static long getSize(File file, boolean followSymlinks)
			throws IOException {
		// Store the total size of all files
		long size = 0;
		boolean symlink = false;
		
		if (!symlink) {
			if (file.isDirectory()) {
				// All files and subdirectories
				File[] files = file.listFiles();
				for (int i = 0; i < files.length; i++) {
					// Recursive call
						size += getSize(files[i], followSymlinks);
				}
			}
			// Base case
			else {
				size += file.length();
			}
		}
		return size;
	}
	
		

	public static long getCount(File file, boolean followSymlinks) throws IOException {
		// Store the total size of all files
		long count = 0;
		boolean symlink = false;
		
		if (!symlink) {
		if (file.isDirectory()) {
			// All files and subdirectories
			File[] files = file.listFiles();
			for (int i = 0; i < files.length; i++) {
				if (files[i].isFile())
					count++;
				else
					count = count + getCount(files[i],followSymlinks);
			}
		}
			
		}
		return count;
	}
	
	

}
