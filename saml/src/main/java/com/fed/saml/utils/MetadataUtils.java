package com.fed.saml.utils;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Random;

public class MetadataUtils {

	public static final String getRandomNumber() {
		Random random = new Random(); 		
		return Integer.toString(random.nextInt(1000));
	}
	
	public static final String getValidUntilDate() {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");			
		Calendar calendar = new GregorianCalendar();	
		calendar.add(Calendar.YEAR, 10);
		return sdf.format(calendar.getTime()).toString();
	}
}
