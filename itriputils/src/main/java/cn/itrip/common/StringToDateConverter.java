package cn.itrip.common;

import java.text.SimpleDateFormat;
import java.util.Date;

import org.springframework.core.convert.converter.Converter;

public class StringToDateConverter implements Converter<String,Date> {
	private String datePattern;
	
	public StringToDateConverter(String datePattern) {
		System.out.println("StringToDateConverter convert:" + datePattern);
		this.datePattern = datePattern;
	}

	public Date convert(String s) {
		Date date = null;
		try {
			date = new SimpleDateFormat(datePattern).parse(s);
			System.out.println("StringToDateConverter convert date:" + date);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return date;
	}
	
}
