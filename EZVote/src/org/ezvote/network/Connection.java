package org.ezvote.network;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * abstract class, used for transport data between participants 
 * @author Red
 */
public abstract class Connection {
	public abstract InputStream getInputStream();
	public abstract OutputStream getOutputStream();
	public abstract String recvLine();
	public abstract void send(String s);
}
