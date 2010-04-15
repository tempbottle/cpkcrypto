package org.ezvote.authority;

import java.util.Vector;

public class Result {
	private Vector<Integer> _yesCnts;
	private Vector<String> _options;
	
	public Result(int cnt){
		_yesCnts = new Vector<Integer>(cnt);
		_options = new Vector<String>(cnt);
	}
	
	public void addResult(Integer yesCnt, String option){
		_yesCnts.add(yesCnt);
		_options.add(option);
	}
	
	public String getOption(int idx){
		return _options.get(idx);
	}
	
	public Integer getYesCnt(int idx){
		return _yesCnts.get(idx);
	}
}
