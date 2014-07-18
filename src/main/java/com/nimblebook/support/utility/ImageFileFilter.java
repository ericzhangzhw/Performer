package com.nimblebook.support.utility;

import java.io.File;
import java.io.FileFilter;

public class ImageFileFilter implements FileFilter {
	
	@Override
	public boolean accept(File pathname) {
		return Constants.PREVIEW_IMG_TYPE.equals(getExt(pathname.getName()));
	}
	
	private String getExt(String s) {
		if (s == null) return null;
	    int i = s.lastIndexOf('.');
	    if(i>0 && i < s.length()-1) return s.substring(i+1).toLowerCase();
		return null;
	}

}