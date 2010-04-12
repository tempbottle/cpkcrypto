package org.ezvote.manager;

public interface EligibilityRule {
	
	/**
	 * check if `id' is eligible
	 */
	public boolean isEligible(String id);
}
