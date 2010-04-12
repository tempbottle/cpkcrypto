package org.ezvote.manager;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegexRule implements EligibilityRule {
	
	Pattern _pattern;
	
	public RegexRule(String rule){
		_pattern = Pattern.compile(rule);
	}

	@Override
	public boolean isEligible(String id) {
		Matcher m = _pattern.matcher(id);
		return m.matches();
	}

}
